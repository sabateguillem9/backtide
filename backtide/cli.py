"""Command-line entry point: `backtide`. Messages for the user are in Spanish."""

import argparse
import logging
import os
import signal
import stat
import sys
import textwrap
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime, tzinfo
from pathlib import Path

from backtide import __version__, shell_cli
from backtide.blackbox import BlackBox, BlackBoxError, Problem, VerifyReport, load_key, redact
from backtide.jail import ExposedJail, JailError
from backtide.jail.profile import ProfileError
from backtide.jail.profiles import DEFAULT_PROFILE
from backtide.service.config import ConfigError, ServiceConfig
from backtide.service.control import (
    OUTCOME_EXIT_CODES,
    ControlError,
    ControlOutcomeUnknown,
    ControlUnavailable,
    ask_rewind,
)
from backtide.service.gasto import caps as spending_caps
from backtide.service.gasto import spending
from backtide.service.guardian import BOOT_STOP_FAILED_NOTE
from backtide.service.notice import ago, rewind_notice
from backtide.service.offline import rewind_without_service
from backtide.service.retenidas import decide as decide_hold
from backtide.service.retenidas import listing as list_holds
from backtide.service.runner import ServiceLocked, ServiceRunning, serve, take_lock
from backtide.service.seguir import seguir
from backtide.setup import layout, preflight
from backtide.setup.host import SystemHost
from backtide.snapshots import Snapshot, SnapshotError, SnapshotStore

logger = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_TAMPERED = 1  # verificar: the black box is not intact
EXIT_FAILED = 1  # vigilar: the service could not run, or could not stop the agent
EXIT_ERROR = 2  # usage errors (argparse also exits with 2) and unreadable inputs
EXIT_PROBLEM = 3  # rebobinar: rewound, but something went wrong afterwards (or cannot tell)
NOT_VERIFIED = "NO VERIFICADA: trátala como no íntegra"
MAX_LISTED_PROBLEMS = 50
DEFAULT_CONFIG = layout.CONFIG_FILE
DEFAULT_LISTED_SNAPSHOTS = 30  # docs/19, decision 21
# Only `backtide rebobinar` says this: the rest of the notice is backtide/service/notice.py.
REWIND_NOTICE_WITHOUT_SERVICE = (
    "Si no hay un servicio de backtide en marcha (`backtide vigilar`), el rebobinado se hace aquí "
    "y el agente se queda parado: arráncalo después con `backtide vigilar`."
)
YES_ANSWERS = frozenset({"s", "si", "sí"})
REASON_NAMES = {
    "periodic": "periódica",
    "manual": "manual",
    "pre_restore": "antes de rebobinar",
    "recovered": "recuperada",
    "evidence": "de evidencia",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="backtide",
        description="Black box for AI agents: record, rewind and stop the irreversible.",
    )
    parser.add_argument("--version", action="version", version=f"backtide {__version__}")
    commands = parser.add_subparsers(dest="command", metavar="<comando>")
    verify = commands.add_parser(
        "verificar",
        help="comprueba que la caja negra está íntegra",
        description="Comprueba la cadena de huellas de la caja negra y su punto de control. "
        "Sale con 0 si está íntegra, 1 si hay manipulación y 2 si no se puede leer. "
        "Cualquier salida distinta de 0 debe tratarse como una alerta.",
    )
    verify.add_argument("--db", required=True, type=Path, help="base de datos de la caja negra")
    verify.add_argument("--key", required=True, type=Path, help="archivo de la clave")
    verify.add_argument("--checkpoint", type=Path, help="archivo del punto de control")
    verify.set_defaults(handler=_verify)

    watch = commands.add_parser(
        "vigilar",
        help="arranca el servicio: vigila al agente en primer plano",
        description="Arranca a backtide en primer plano: graba al agente, hace instantáneas de su "
        "carpeta cuando cambia algo y lo para si backtide se para. Ctrl-C o SIGTERM paran a "
        "backtide y, con él, al agente. Sale con 0 si paró bien, 1 si no pudo arrancar o no pudo "
        "parar al agente y 2 si la configuración no sirve.",
    )
    _add_config(watch)
    watch.add_argument(
        "--grupo-web",
        dest="web_group",
        metavar="GRUPO",
        help="abre también el socket estrecho de la web (web.sock, 0660) para ese grupo: la web "
        "instalada aprueba, rechaza, rebobina y cambia los ajustes por él, y nada más (T12c)",
    )
    watch.set_defaults(handler=_watch)

    listing = commands.add_parser(
        "instantaneas",
        help="lista las instantáneas, de la más nueva a la más vieja",
        description="Lista las instantáneas del espacio de trabajo del agente. No hace falta que "
        "el servicio esté en marcha.",
    )
    _add_config(listing)
    listing.add_argument(
        "--todas",
        action="store_true",
        help=f"todas, no solo las {DEFAULT_LISTED_SNAPSHOTS} más nuevas",
    )
    listing.set_defaults(handler=_list_snapshots)

    rewind = commands.add_parser(
        "rebobinar",
        help="vuelve el espacio de trabajo del agente a una instantánea",
        description="Vuelve el espacio de trabajo del agente a una instantánea: copia el "
        "identificador de la primera columna de `backtide instantaneas`. Enseña qué se deshace y "
        "qué no, y pide confirmación (`--si` la da por hecha; sin terminal es obligatorio). "
        "Con un servicio en marcha se lo pide a él por el socket de control y el agente "
        "vuelve a arrancar; sin servicio rebobina en este proceso y el agente se queda "
        "parado. Se guarda un punto para deshacer, que se muestra al terminar. Sale con 0 si "
        "se rebobinó, 1 si no se hizo y el espacio de trabajo no cambió, 2 si hay un error de "
        "uso o de lectura y 3 si se rebobinó pero con un problema (o no se sabe).",
    )
    _add_config(rewind)
    rewind.add_argument("snapshot", metavar="instantánea", help="identificador de la instantánea")
    rewind.add_argument("--si", action="store_true", help="no pedir confirmación")
    rewind.set_defaults(handler=_rewind)

    resume = commands.add_parser(
        "seguir",
        help="reanuda al agente tras una pausa por falta de espacio",
        description="Reanuda al agente que backtide pausó por falta de espacio (o por no poder "
        "grabar). Se lo pide al servicio en marcha, que se niega mientras siga faltando "
        "espacio. Sale con 0 si el agente sigue (o no había pausa), 1 si no se reanudó, 2 si "
        "hay un error de uso y 3 si no se sabe o se reanudó con un problema.",
    )
    _add_config(resume)
    resume.set_defaults(handler=_resume)
    _add_holds(commands)
    _add_spending(commands)
    _add_check(commands)
    _add_web(commands)
    _add_shell(commands)
    return parser


def _add_shell(commands: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    """`backtide entrar`, `tarea`, `importar` and `exportar` (T17a-4), through the running service
    (backtide/shell_cli.py): `tarea` for Claude Code and OpenClaw (D27), `entrar`, `importar` and
    `exportar` only for an agent of the shell mode (Claude Code)."""
    enter = commands.add_parser(
        "entrar",
        help="abre el agente de programación en tu terminal (claude-code)",
        description="Abre Claude Code dentro de su jaula, conectado a este terminal, como el "
        "usuario del agente y en su carpeta de trabajo. Se lo pide antes al servicio en marcha, "
        "que lo graba. Todo lo que haga el agente queda grabado y se puede rebobinar. Con "
        "OpenClaw no hay sesión en la terminal por ahora: háblale con `backtide tarea` o por "
        "Telegram. Sale con 0 si la sesión terminó bien, 1 si no se pudo abrir o "
        "terminó con error y 2 si hay un error de uso (por ejemplo, un agente sin sesión).",
    )
    _add_config(enter)
    enter.add_argument(
        "--continue",
        dest="resume",
        action="store_true",
        help="sigue la última conversación (la de la instantánea, tras un rebobinado)",
    )
    enter.set_defaults(handler=_enter)

    task = commands.add_parser(
        "tarea",
        help='le da una tarea al agente y enseña su respuesta: tarea "…"',
        description="Lanza dentro de la jaula `claude -p` (Claude Code) o un turno de `openclaw "
        "agent` por su Gateway (OpenClaw, en su conversación principal, la misma de Telegram), "
        "con la tarea como un solo argumento, y enseña la respuesta. Se lo pide antes al "
        "servicio en marcha, que lo graba junto con el principio de lo que pides (tachado lo que "
        "parezca un secreto). Ctrl-C la para dentro del agente. Sale con 0 si la tarea terminó "
        "bien, 1 si no, 2 si hay un error de uso y 3 si no se sabe (por ejemplo, se cortó con "
        "Ctrl-C o falló docker: la tarea puede seguir dentro).",
    )
    _add_config(task)
    task.add_argument("prompt", metavar="tarea", help="lo que le pides, entre comillas")
    task.add_argument(
        "--continue",
        dest="resume",
        action="store_true",
        help="sigue la última conversación (la de la instantánea, tras un rebobinado); con "
        "OpenClaw no cambia nada: siempre sigue la suya",
    )
    task.add_argument(
        "--minutos",
        type=float,
        default=None,
        help="tiempo máximo, con decimales si hace falta (por defecto 60 con Claude Code y 15 "
        "con OpenClaw)",
    )
    task.set_defaults(handler=_task)

    bring = commands.add_parser(
        "importar",
        help="copia una carpeta de este ordenador a la carpeta de trabajo del agente",
        description="Copia una carpeta del anfitrión a /workspace/work/<nombre> del agente, como "
        "el usuario del agente. No sigue enlaces simbólicos (los salta y dice cuáles), solo "
        "copia archivos y carpetas, tiene un tope de tamaño y nunca escribe encima de una "
        "carpeta que ya existe salvo con --reemplazar. Deja fuera lo que parece un secreto salvo "
        "con --incluir-secretos, y nunca importa tu carpeta personal ni ~/.ssh o ~/.aws. El "
        "servicio lo graba antes. Sale con 0 si "
        "se importó, 1 si no se pudo, 2 si hay un error de uso y 3 si quedó a medias.",
    )
    _add_config(bring)
    bring.add_argument("source", metavar="carpeta", help="la carpeta del anfitrión")
    bring.add_argument("--nombre", help="nombre de la carpeta en el agente (por defecto, el mismo)")
    bring.add_argument(
        "--reemplazar", action="store_true", help="escribe encima si la carpeta ya existe"
    )
    bring.add_argument(
        "--incluir-secretos",
        action="store_true",
        dest="incluir_secretos",
        help="copia también lo que parece un secreto (.env, claves, .npmrc, una URL de git con "
        "contraseña…): por defecto se deja fuera y se dice qué",
    )
    bring.set_defaults(handler=_import)

    take = commands.add_parser(
        "exportar",
        help="copia la carpeta de trabajo del agente a una carpeta nueva de este ordenador",
        description="El servicio hace una instantánea y copia de ella /workspace/work a la "
        "carpeta que digas, que no puede existir (nunca se sobrescribe nada). No sigue enlaces "
        "simbólicos ni copia lo que no es un archivo o una carpeta, ni ningún repositorio de git "
        "(su configuración podría ejecutar código aquí), ni, salvo con --incluir-config, lo que "
        "tus herramientas pueden ejecutar o leer solas al abrir la carpeta: todo lo que empieza "
        "por punto (.claude/, .mcp.json, .vscode/, .envrc, .github/…) salvo unos pocos archivos "
        "inofensivos (.gitignore, .editorconfig, .python-version…), y CLAUDE.md, AGENTS.md, "
        "GEMINI.md, las configuraciones de MCP y los *.code-workspace. "
        "Con --git <carpeta>, el agente hace "
        "dentro de la jaula un bundle de git de ese repositorio y solo sale ese archivo, a la "
        "ruta nueva que digas: los commits, sin configuración ni hooks. Lo exportado lo escribió "
        "el agente: revísalo antes de ejecutar nada de ahí. Queda grabado. Sale con 0 si se "
        "exportó, 1 si no se pudo, 2 si hay un error de uso y 3 si no se sabe.",
    )
    _add_config(take)
    take.add_argument("destination", metavar="ruta", help="carpeta (o bundle) nueva donde copiarla")
    take.add_argument(
        "--git",
        metavar="carpeta",
        help="saca solo los commits de ese repositorio de /workspace/work, como un bundle de git "
        "(`.` para la carpeta de trabajo entera)",
    )
    take.add_argument(
        "--incluir-config",
        action="store_true",
        dest="incluir_config",
        help="copia también lo que Claude Code, tu editor o direnv pueden ejecutar o leer solos al "
        "abrir la carpeta (lo que empieza por punto, CLAUDE.md, AGENTS.md…): por defecto se deja "
        "fuera y se dice qué",
    )
    take.set_defaults(handler=_export)


def _shell_config(args: argparse.Namespace) -> ServiceConfig | None:
    try:
        return ServiceConfig.from_file(args.config)
    except ConfigError as error:
        _error(f"configuración no válida: {error}")
        return None


def _enter(args: argparse.Namespace) -> int:
    config = _shell_config(args)
    return EXIT_ERROR if config is None else shell_cli.entrar(config, resume=args.resume)


def _task(args: argparse.Namespace) -> int:
    config = _shell_config(args)
    if config is None:
        return EXIT_ERROR
    return shell_cli.tarea(config, args.prompt, resume=args.resume, minutes=args.minutos)


def _import(args: argparse.Namespace) -> int:
    config = _shell_config(args)
    if config is None:
        return EXIT_ERROR
    return shell_cli.importar(
        config,
        args.source,
        name=args.nombre,
        replace=args.reemplazar,
        include_secrets=args.incluir_secretos,
    )


def _export(args: argparse.Namespace) -> int:
    config = _shell_config(args)
    if config is None:
        return EXIT_ERROR
    return shell_cli.exportar(
        config, args.destination, git=args.git, include_config=args.incluir_config
    )


def _add_holds(commands: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    """`backtide retenidas`, `aprobar` and `rechazar` (T10-2): the requests the gate holds."""
    listing = commands.add_parser(
        "retenidas",
        help="lista las peticiones del agente que esperan tu aprobación",
        description="Lista las peticiones a internet que la puerta retiene hasta que decidas "
        "(borrados, envíos, escrituras): su identificador, su riesgo y lo que piden. Se lo "
        "pregunta al servicio en marcha. Sale con 0 si las lista, 1 si no hay servicio y 2 si "
        "hay un error.",
    )
    _add_config(listing)
    listing.set_defaults(handler=_list_holds)
    for name, verdict, says in (
        ("aprobar", "approve", "deja salir una petición retenida, una sola vez"),
        ("rechazar", "reject", "rechaza una petición retenida: no sale"),
    ):
        command = commands.add_parser(
            name,
            help=says,
            description=f"{says[0].upper()}{says[1:]}. El identificador (h-…) sale en "
            "`backtide retenidas` y en el aviso. Se lo pide al servicio en marcha. Sale con 0 si "
            "se decidió, 1 si no había esa retención abierta (ya decidida, caducada o tras un "
            "reinicio), 2 si hay un error de uso y 3 si no se sabe.",
        )
        _add_config(command)
        command.add_argument("hold", metavar="id", help="identificador de la petición (h-…)")
        command.set_defaults(handler=_decide_hold, verdict=verdict)


def _add_spending(commands: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    """`backtide gasto` and `backtide tope` (T11): the spending cap, through the running service."""
    spent = commands.add_parser(
        "gasto",
        help="lo gastado hoy y este mes en el modelo, frente al tope",
        description="Dice cuánto ha gastado el agente en llamadas al modelo hoy y este mes, "
        "frente a los topes, y si alguno está alcanzado. Se lo pregunta al servicio en marcha. "
        "Sale con 0 si lo dice, 1 si no hay servicio o no puede contar, 2 si hay un error.",
    )
    _add_config(spent)
    spent.set_defaults(handler=_spending)
    caps = commands.add_parser(
        "tope",
        help="muestra o cambia el tope de gasto diario y mensual",
        description="Sin opciones, muestra el tope diario y el mensual. Con `--dia` y/o `--mes` "
        "(dólares, con dos decimales como mucho) los cambia por el mismo camino que la página "
        "Ajustes de la web: el servicio lo apunta en la caja negra antes de cambiar nada y se "
        "aplica a la siguiente llamada al modelo. Sale con 0 si lo hizo, 1 si no hay servicio o "
        "no se guardó, 2 si el importe no vale o hay un error y 3 si no se sabe.",
    )
    _add_config(caps)
    caps.add_argument("--dia", dest="day", metavar="N", help="nuevo tope diario, en dólares")
    caps.add_argument("--mes", dest="month", metavar="N", help="nuevo tope mensual, en dólares")
    caps.set_defaults(handler=_caps)


def _add_check(commands: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    """`backtide comprobar` (T13-2): the installer's preflight, for anyone, at any time; with
    `--despues-de-instalar` (T13-3), the self-test of an installed backtide."""
    check = commands.add_parser(
        "comprobar",
        help="comprueba si esta máquina sirve para backtide",
        description="Repasa lo que backtide necesita de esta máquina (kernel, Btrfs, cgroup v2, "
        "systemd, BTF para el sensor de procesos, espacio, Docker, SELinux o AppArmor, las redes "
        "de Docker frente a una VPN o la LAN...) y dice cómo arreglar lo que falte. No cambia "
        "nada. Con `sudo` lo ve todo. Con --despues-de-instalar, como root, prueba además la "
        "instalación de verdad: las unidades, el agente bajo backtide y su confinamiento, que no "
        "sale sin el proxy, la caja negra, el sensor y la web. Sale con 0 si no hay ningún fallo "
        "(los avisos no cuentan) y 1 si hay alguno.",
    )
    check.add_argument(
        "--despues-de-instalar",
        dest="installed",
        action="store_true",
        help="prueba backtide ya instalado (la autoprueba del instalador); hace falta root",
    )
    _add_config(check)
    check.set_defaults(handler=_check)

    images = commands.add_parser(
        "imagenes",
        help="lista las imágenes que usa esta versión, fijadas por digest",
        description="Imprime las imágenes de Docker que esta versión de backtide usa (cada "
        "agente, el proxy y el sensor), cada una fijada por su digest. Es la única lista: el "
        "instalador descarga de ellas las de su agente (--perfil) y comprueba el digest.",
    )
    images.set_defaults(handler=_images)

    install = commands.add_parser(
        "instalar",
        help="instala backtide en esta máquina (lo llama install.sh)",
        description="Instala backtide como servicio de systemd: comprueba la máquina, instala lo "
        "que falte (con permiso), crea el volumen del agente, las claves, las redes y las "
        "unidades, arranca el servicio y su web, y prueba que todo funciona. Se puede ejecutar "
        "otra vez sin romper nada: solo hace lo que falte. Las claves nunca van en un argumento: "
        "--clave-archivo dice dónde leerla, --clave-stdin la lee de la entrada estándar y, con "
        "terminal, se pide sin eco; el token de Telegram (--telegram), igual. Con --clave-stdin "
        "y --telegram-token-stdin a la vez, la clave va en la primera línea y el token en la "
        "segunda. El agente es OpenClaw, o Claude Code con --perfil claude-code; para cambiarlo, "
        "desinstala antes. Hace falta root. Sale con 0 si queda instalado y probado, 1 si se paró "
        "(dice dónde y cómo seguir) y 2 si hay un error de uso.",
    )
    install.add_argument("--si", action="store_true", help="contesta que sí a todas las preguntas")
    install.add_argument(
        "--dry-run", action="store_true", help="enseña lo que haría y no cambia nada"
    )
    install.add_argument(  # install.sh's check before it switches the release (D27)
        "--solo-comprobar", action="store_true", help=argparse.SUPPRESS
    )
    install.add_argument(
        "--perfil",
        choices=("openclaw", "claude-code"),  # backtide.setup.install.PROFILES
        help="el agente que va en la jaula: openclaw (por defecto) o claude-code; una vez "
        "instalado se queda el suyo",
    )
    install.add_argument(
        "--proveedor",
        choices=("anthropic", "openai"),
        default="anthropic",
        help="el proveedor del modelo cuya clave se guarda (por defecto anthropic)",
    )
    keys = install.add_mutually_exclusive_group()
    keys.add_argument(
        "--clave-archivo",
        type=Path,
        metavar="RUTA",
        help="lee la clave del modelo de este archivo (una línea); bórralo después",
    )
    keys.add_argument(
        "--clave-stdin", action="store_true", help="lee la clave del modelo de la entrada estándar"
    )
    keys.add_argument(
        "--sin-clave",
        action="store_true",
        help="no pide la clave: la pondrás después en la web (`sudo backtide enlace`), "
        "Ajustes > Modelos",
    )
    install.add_argument(
        "--telegram",
        action="store_true",
        help="pone el bot de Telegram: pide su token sin eco y tu chat (sin esto, se pone "
        "después en la web, Ajustes > Avisos)",
    )
    tokens = install.add_mutually_exclusive_group()
    tokens.add_argument(
        "--telegram-token-archivo",
        type=Path,
        metavar="RUTA",
        help="con --telegram, lee el token del bot de este archivo (una línea); bórralo después",
    )
    tokens.add_argument(
        "--telegram-token-stdin",
        action="store_true",
        help="con --telegram, lee el token del bot de la entrada estándar",
    )
    install.add_argument(
        "--telegram-chat",
        metavar="NUMERO",
        help="con --telegram, el número de tu chat privado con el bot (si no, se pregunta)",
    )
    install.add_argument("--tope-diario", metavar="DOLARES", help="tope de gasto diario (5)")
    install.add_argument("--tope-mensual", metavar="DOLARES", help="tope de gasto mensual (50)")
    install.add_argument(
        "--zona-horaria", metavar="ZONA", help="zona horaria del día del tope (la de la máquina)"
    )
    install.add_argument(
        "--subredes",
        metavar="A,B",
        help="las subredes de las redes del agente (A) y de salida (B), si no valen las que elige",
    )
    install.add_argument(
        "--volumen-gib",
        type=int,
        default=layout.VOLUME_SIZE // layout.GIB,
        metavar="N",
        help=f"tamaño máximo del volumen del agente, disperso (por defecto "
        f"{layout.VOLUME_SIZE // layout.GIB})",
    )
    install.set_defaults(handler=_install)

    uninstall = commands.add_parser(
        "desinstalar",
        help="quita backtide de esta máquina; por defecto conserva los datos",
        description="Quita lo que creó `backtide instalar`, y solo eso (lo dice su manifiesto): "
        "para el agente, quita las unidades, los contenedores, las redes y las imágenes de "
        "backtide, /etc/backtide, /opt/backtide, la orden y el usuario backtide-web, y deja los "
        "ajustes de Docker como estaban. Por defecto CONSERVA los datos en /var/lib/backtide: la "
        "caja negra y su clave, el volumen con el trabajo del agente y sus instantáneas, y las "
        "claves; instalar otra vez sigue con ellos. Docker se queda salvo con --quitar-docker. Se "
        "puede ejecutar otra vez: sigue donde se quedó. Hace falta root. Sale con 0 si queda "
        "desinstalado (o no había nada), 1 si se paró y 2 si hay un error de uso.",
    )
    uninstall.add_argument(
        "--borrar-datos",
        action="store_true",
        help="borra también los datos, para siempre: pide escribir el nombre de la máquina",
    )
    uninstall.add_argument(
        "--quitar-docker",
        action="store_true",
        help="quita también Docker, su repositorio y su clave, si los instaló backtide y no hay "
        "otros contenedores",
    )
    uninstall.add_argument("--si", action="store_true", help="no pregunta (ni el nombre)")
    uninstall.add_argument(
        "--dry-run", action="store_true", help="enseña lo que quitaría y no cambia nada"
    )
    uninstall.set_defaults(handler=_uninstall)


def _check(args: argparse.Namespace) -> int:
    """`backtide comprobar` and `backtide comprobar --despues-de-instalar`."""
    if not args.installed:
        checks = preflight.run_checks(SystemHost(), installing=False)
        print(preflight.report(checks))
        return EXIT_FAILED if preflight.failed(checks) else EXIT_OK
    from backtide.setup import selftest
    from backtide.setup.host import run as host_run

    if _effective_uid() != 0:
        _error("la autoprueba de la instalación necesita root: `sudo backtide comprobar "
               "--despues-de-instalar`.")  # fmt: skip
        return EXIT_ERROR
    config = _load_config(args)
    if config is None:
        return EXIT_ERROR
    print("Probando la instalación (el primer arranque del agente tarda unos minutos)...")
    checks = selftest.run_selftest(config, SystemHost(), run=host_run)
    print(preflight.report(checks, installed=True))
    return EXIT_FAILED if preflight.failed(checks) else EXIT_OK


def _images(args: argparse.Namespace) -> int:
    from backtide.setup import images

    print(images.listing())
    return EXIT_OK


def _install(args: argparse.Namespace) -> int:
    """`backtide instalar` (T13-3): backtide.setup.install does the work."""
    from decimal import Decimal, InvalidOperation
    from functools import partial

    from backtide.setup import install, selftest
    from backtide.setup.host import run as host_run

    if _effective_uid() != 0 and not args.dry_run:
        _error("instalar necesita root: `sudo backtide instalar` (o `sudo sh install.sh`).")
        return EXIT_ERROR
    try:
        daily = Decimal(args.tope_diario) if args.tope_diario is not None else None
        monthly = Decimal(args.tope_mensual) if args.tope_mensual is not None else None
    except InvalidOperation:
        _error("los topes son números de dólares, como 5 o 12.50")
        return EXIT_ERROR
    if not 1 <= args.volumen_gib <= 4096:
        _error("--volumen-gib va de 1 a 4096")
        return EXIT_ERROR
    if args.perfil == "claude-code" and args.proveedor != "anthropic":
        _error("Claude Code solo habla con la API de Anthropic: --proveedor anthropic")
        return EXIT_ERROR
    telegram = bool(
        args.telegram
        or args.telegram_token_archivo is not None
        or args.telegram_token_stdin
        or args.telegram_chat is not None
    )
    options = install.Options(
        yes=args.si,
        dry_run=args.dry_run,
        provider=args.proveedor,
        key_file=args.clave_archivo,
        key_stdin=args.clave_stdin,
        no_key=args.sin_clave,
        daily_usd=daily,
        monthly_usd=monthly,
        timezone=args.zona_horaria,
        subnets=args.subredes,
        volume_size=args.volumen_gib * layout.GIB,
        profile=args.perfil,
        telegram=telegram,
        telegram_token_file=args.telegram_token_archivo,
        telegram_token_stdin=args.telegram_token_stdin,
        telegram_chat=args.telegram_chat,
    )
    host = SystemHost()
    installer = install.Installer(
        host=host,
        run=host_run,
        run_long=partial(host_run, timeout=3600.0),
        prompter=TerminalPrompter(),
        options=options,
        self_test=lambda config: selftest.run_selftest(config, host, run=host_run),
        release=Path(__file__).resolve().parents[1],
    )
    if args.solo_comprobar:
        try:
            installer.check_options()
        except install.InstallError as error:
            _error(f"la instalación se ha parado: {error}")
            return EXIT_FAILED
        return EXIT_OK
    try:
        installer.install()
    except install.InstallError as error:
        _error(f"la instalación se ha parado: {error}")
        _error("Lo hecho hasta aquí está apuntado; vuelve a ejecutar el instalador para seguir.")
        return EXIT_FAILED
    except KeyboardInterrupt:
        _error("interrumpido: vuelve a ejecutar el instalador para seguir donde se quedó.")
        return EXIT_FAILED
    return EXIT_OK


def _uninstall(args: argparse.Namespace) -> int:
    """`backtide desinstalar` (T13-4): backtide.setup.uninstall does the work."""
    import time
    from functools import partial

    from backtide.setup import uninstall
    from backtide.setup.host import run as host_run

    if _effective_uid() != 0:
        _error("desinstalar necesita root: `sudo backtide desinstalar`.")
        return EXIT_ERROR
    remover = uninstall.Uninstaller(
        host=SystemHost(),
        run=host_run,
        run_long=partial(host_run, timeout=1800.0),
        prompter=TerminalPrompter(),
        options=uninstall.Options(
            yes=args.si,
            erase_data=args.borrar_datos,
            remove_docker=args.quitar_docker,
            dry_run=args.dry_run,
        ),
        sleep=time.sleep,
    )
    try:
        remover.uninstall()
    except uninstall.UninstallError as error:
        _error(f"la desinstalación se ha parado: {error}")
        if remover.started:
            _error("Lo hecho hasta aquí está apuntado; vuelve a ejecutarla para seguir.")
        return EXIT_FAILED
    except KeyboardInterrupt:
        _error("interrumpido: vuelve a ejecutar `sudo backtide desinstalar` para seguir.")
        return EXIT_FAILED
    return EXIT_OK


class TerminalPrompter:
    """Questions and keys through /dev/tty, so they work under `curl ... | sudo sh` too."""

    TTY = "/dev/tty"

    def __init__(self) -> None:
        try:
            with open(self.TTY, "rb"):
                self.interactive = True
        except OSError:
            self.interactive = False

    def say(self, text: str) -> None:
        print(text, flush=True)

    def confirm(self, question: str) -> bool:
        with open(self.TTY, "r+", encoding="utf-8", errors="replace") as tty:
            tty.write(f"{question} [s/N] ")
            tty.flush()
            return tty.readline().strip().lower() in YES_ANSWERS

    def answer(self, question: str) -> str:
        with open(self.TTY, "r+", encoding="utf-8", errors="replace") as tty:
            tty.write(question)
            tty.flush()
            return tty.readline().strip()

    def secret(self, prompt: str) -> str:
        import getpass

        return getpass.getpass(prompt)


def _add_config(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG,
        help=f"archivo de configuración (por defecto {DEFAULT_CONFIG})",
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return EXIT_OK
    return args.handler(args)


def _verify(args: argparse.Namespace) -> int:
    # Never create a database while verifying: a missing one is an error, not an empty box.
    if not args.db.is_file():
        _error(f"no existe la base de datos de la caja negra: {args.db}")
        return EXIT_ERROR
    try:
        key = load_key(args.key)
    except BlackBoxError as exc:
        _error(f"clave no válida: {exc}")
        return EXIT_ERROR
    try:
        # Read-only: verifying never writes to the evidence, not even to an empty file.
        with BlackBox(args.db, key, checkpoint_path=args.checkpoint, readonly=True) as box:
            report = box.verify()
    except BlackBoxError as exc:
        _error(f"no se puede leer la caja negra: {exc}")
        print(NOT_VERIFIED, file=sys.stderr)
        return EXIT_ERROR
    _print_report(report)
    return EXIT_OK if report.ok else EXIT_TAMPERED


def _web_user(name: str | None) -> int | None:
    """The uid of the account named like the web's group (the installed ``backtide-web``), so
    the narrow socket takes that user only; None if there is no such account."""
    import pwd

    try:
        return None if name is None else pwd.getpwnam(name).pw_uid
    except KeyError:
        return None


def _web_group(name: str | None) -> int | str | None:
    """The gid of `vigilar --grupo-web` (T12c), None without it, or why it cannot be (text)."""
    if name is None:
        return None
    import grp

    from backtide.service.web_control import web_group_problem

    try:
        gid = grp.getgrnam(name).gr_gid
    except KeyError:
        return f"no existe el grupo {name!r}"
    problem = web_group_problem(gid)
    return f"el grupo {name!r} ({gid}) no sirve: {problem}" if problem else gid


def _watch(args: argparse.Namespace) -> int:
    try:
        config = ServiceConfig.from_file(args.config)
    except ConfigError as error:
        _error(f"configuración no válida: {error}")
        return EXIT_ERROR
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    web_group = _web_group(getattr(args, "web_group", None))
    if isinstance(web_group, str):
        _error(f"--grupo-web: {web_group}")
        return EXIT_ERROR
    print("backtide arrancando. Ctrl-C o SIGTERM lo paran, y con él al agente.", flush=True)
    try:
        web = {"web_group": web_group, "web_user": _web_user(args.web_group)}
        serve(config, **({} if web_group is None else web))
    except ProfileError as error:  # OpenClaw's: UnrewindableConfig
        _error(error.notice)  # the alert and the black box already hold the detail
        return EXIT_ERROR
    except ServiceLocked as error:
        _error(str(error))
        return EXIT_FAILED
    except ConfigError as error:  # a file the service reads at start (telegram.toml, T09)
        _error(f"configuración no válida: {error}")
        return EXIT_ERROR
    except ControlError as error:  # the guardian stopped (and the agent with it) before this
        _error(f"no se puede abrir el socket de control, así que backtide se ha parado: {error}")
        return EXIT_FAILED
    except BlackBoxError as error:
        _error(f"no se puede usar la caja negra, así que backtide no vigila: {error}")
        for note in getattr(error, "__notes__", []):
            _error(note)
        return EXIT_FAILED
    except ExposedJail as error:  # T14a: refused before the agent could see anything
        notes = list(getattr(error, "__notes__", []))
        running = error.still_running or any(n.startswith(BOOT_STOP_FAILED_NOTE) for n in notes)
        _error(
            "backtide no arranca al agente: su contenedor vería algo del anfitrión que no debe "
            f"ver (invariantes 1 y 2). Corrige la configuración y vuelve a arrancar: {error}"
        )
        for note in notes:
            _error(note)
        if running:
            _error(
                "EL AGENTE SIGUE EN MARCHA y backtide no ha podido pararlo. Páralo con "
                f"`docker kill {config.jail_config().name}`."
            )
            return EXIT_FAILED
        return EXIT_ERROR
    except JailError as error:
        _error(f"EL AGENTE SIGUE EN MARCHA y backtide no ha podido pararlo: {error}")
        return EXIT_FAILED
    except Exception as error:  # nothing on this path is swallowed: it is logged with its trace
        logger.exception("backtide vigilar failed")
        _error(f"error inesperado, backtide se ha parado: {type(error).__name__}: {error}")
        _error(
            "No se sabe si el agente sigue en marcha. Compruébalo con "
            f"`docker ps --filter name={config.jail_config().name}` y, si aparece, páralo con "
            f"`docker stop {config.jail_config().name}`."
        )
        return EXIT_FAILED
    print("backtide parado. El agente está parado.")
    return EXIT_OK


def _list_snapshots(args: argparse.Namespace) -> int:
    try:
        config = ServiceConfig.from_file(args.config)
        snapshots = SnapshotStore(config.volume).snapshots()
    except ConfigError as error:
        _error(f"configuración no válida: {error}")
        return EXIT_ERROR
    except SnapshotError as error:
        _error(f"no se pueden leer las instantáneas: {error}")
        return EXIT_ERROR
    for line in _snapshot_lines(
        snapshots,
        now=_now(),
        tz=_local_tz(),
        limit=None if args.todas else DEFAULT_LISTED_SNAPSHOTS,
    ):
        print(line)
    return EXIT_OK


def _rewind(args: argparse.Namespace) -> int:
    """`backtide rebobinar`: the notice, the confirmation, and then the rewind through the running
    service (the lock is taken: its socket) or, if there is none, in this process. Never both:
    with the lock taken by somebody else this process does not touch the agent."""
    target = Snapshot.parse(args.snapshot)
    if target is None:
        _error(
            "eso no es el identificador de una instantánea: cópialo de la primera columna de "
            "`backtide instantaneas`"
        )
        return EXIT_ERROR
    try:
        config = ServiceConfig.from_file(args.config)
        known = SnapshotStore(config.volume).snapshots()
    except ConfigError as error:
        _error(f"configuración no válida: {error}")
        return EXIT_ERROR
    except SnapshotError as error:
        _error(f"no se pueden leer las instantáneas: {error}")
        return EXIT_ERROR
    if target not in known:
        _error(f"no existe la instantánea {target.id}: mira `backtide instantaneas`")
        return EXIT_ERROR

    lines = config.agent_profile.rewind_notice_lines
    print(_rewind_notice(target, now=_now(), tz=_local_tz(), agent_lines=lines))
    if not args.si:
        confirmed = _confirm()
        if confirmed is None:
            _error("sin terminal no se puede preguntar: usa --si para confirmar")
            return EXIT_ERROR
        if not confirmed:
            print("No se ha hecho nada.")
            return EXIT_FAILED

    try:
        lock = take_lock(config.lock_file)
    except ServiceRunning:
        return _rewind_through_service(config, target)
    except ServiceLocked as error:  # the lock file itself is unusable: not "a service"
        _error(str(error))
        return EXIT_ERROR
    with lock:
        return _rewind_in_process(config, target)


def _resume(args: argparse.Namespace) -> int:
    """`backtide seguir`: everything but reading the config is in backtide/service/seguir.py."""
    try:
        config = ServiceConfig.from_file(args.config)
    except ConfigError as error:
        _error(f"configuración no válida: {error}")
        return EXIT_ERROR
    return seguir(config)


def _list_holds(args: argparse.Namespace) -> int:
    """`backtide retenidas`: everything but reading the config is in service/retenidas.py."""
    try:
        config = ServiceConfig.from_file(args.config)
    except ConfigError as error:
        _error(f"configuración no válida: {error}")
        return EXIT_ERROR
    return list_holds(config)


def _decide_hold(args: argparse.Namespace) -> int:
    """`backtide aprobar` and `backtide rechazar`."""
    try:
        config = ServiceConfig.from_file(args.config)
    except ConfigError as error:
        _error(f"configuración no válida: {error}")
        return EXIT_ERROR
    return decide_hold(config, args.hold, args.verdict)


def _spending(args: argparse.Namespace) -> int:
    """`backtide gasto`: everything but reading the config is in service/gasto.py."""
    config = _load_config(args)
    return EXIT_ERROR if config is None else spending(config)


def _caps(args: argparse.Namespace) -> int:
    """`backtide tope`."""
    config = _load_config(args)
    return EXIT_ERROR if config is None else spending_caps(config, args.day, args.month)


def _load_config(args: argparse.Namespace) -> ServiceConfig | None:
    try:
        return ServiceConfig.from_file(args.config)
    except ConfigError as error:
        _error(f"configuración no válida: {error}")
        return None


def _rewind_notice(
    target: Snapshot,
    *,
    now: datetime,
    tz: tzinfo,
    agent_lines: Sequence[str] = DEFAULT_PROFILE.rewind_notice_lines,
) -> str:
    notice = rewind_notice(target.taken_at, now=now, tz=tz, agent_lines=agent_lines)
    paragraphs = (*notice, REWIND_NOTICE_WITHOUT_SERVICE)
    return "\n\n".join(textwrap.fill(paragraph, width=88) for paragraph in paragraphs)


def _confirm() -> bool | None:
    """Ask `¿Rebobinar? [s/N]`: True for yes, False for anything else, None without a terminal."""
    if not sys.stdin.isatty():
        return None
    try:
        answer = input("¿Rebobinar? [s/N] ")
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return answer.strip().lower() in YES_ANSWERS


def _rewind_through_service(config: ServiceConfig, target: Snapshot) -> int:
    print("Hay un servicio de backtide en marcha: se lo pido por el socket de control.")
    try:
        reply = ask_rewind(config.control_socket, target.id)
    except ControlUnavailable:
        _error(
            "hay un servicio de backtide que tiene el cerrojo, pero no contesta en el socket de "
            "control: está arrancando o se ha quedado a medias. No se ha tocado nada; inténtalo "
            "de nuevo en un momento."
        )
        return EXIT_FAILED
    except ControlOutcomeUnknown as error:  # the request went out: it may have been done
        _error(str(error))
        return EXIT_PROBLEM
    except ControlError as error:  # nothing was sent
        _error(str(error))
        return EXIT_ERROR
    except KeyboardInterrupt:
        _error(
            "interrumpido. Si el servicio ya había recibido la petición, sigue con el "
            "rebobinado y no se sabe si terminó: mira `backtide instantaneas`."
        )
        return EXIT_PROBLEM
    outcome: str = reply["outcome"]
    return _report_rewind(
        outcome,
        reply["message"],
        reply["undo"],
        agent_line=(
            "El agente está en marcha otra vez."
            if reply["agent_started"]
            else "El agente no se ha arrancado."
        ),
    )


def _rewind_in_process(config: ServiceConfig, target: Snapshot) -> int:
    print("No hay un servicio en marcha: rebobino aquí y el agente se queda parado.")
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_SafeFormatter("%(levelname)s %(name)s: %(message)s"))
    package_logger = logging.getLogger("backtide")
    previous_level = package_logger.level
    package_logger.addHandler(handler)
    package_logger.setLevel(logging.WARNING)
    try:
        with _shielded_from_stop_signals():
            outcome = rewind_without_service(config, target.id)
    except BlackBoxError as error:
        _error(
            f"no se puede usar la caja negra, así que no se rebobina (sin grabar no hay "
            f"vigilancia): {error}"
        )
        for note in getattr(error, "__notes__", []):
            _error(note)
        return EXIT_FAILED
    except JailError as error:  # the black box was unusable and the agent could not be stopped
        _error(f"EL AGENTE SIGUE EN MARCHA y backtide no ha podido pararlo: {error}")
        return EXIT_FAILED
    except Exception as error:  # nothing on this path is swallowed: logged with its trace
        logger.exception("backtide rebobinar failed")
        _error(
            f"error inesperado, no se sabe si se rebobinó: {type(error).__name__}: {error}. "
            "Mira `backtide instantaneas`; el próximo `backtide vigilar` lo concilia."
        )
        return EXIT_PROBLEM
    finally:
        package_logger.removeHandler(handler)
        package_logger.setLevel(previous_level)
    return _report_rewind(
        str(outcome.status),
        outcome.message,
        outcome.undo,
        agent_line="El agente queda parado: arráncalo con `backtide vigilar`.",
    )


def _report_rewind(outcome: str, message: str, undo: str | None, *, agent_line: str) -> int:
    """Print what the rewind did and return the exit code. Everything here may come from the
    service or the agent's world: it is redacted and its control characters escaped."""
    code = OUTCOME_EXIT_CODES[outcome]
    text = _printable(redact(message))
    if code == EXIT_OK:
        print(text)
    elif outcome in ("problem", "unknown"):
        print(f"AVISO: {text}", file=sys.stderr)
    else:
        _error(text)
    if outcome in ("done", "problem"):
        if undo is not None and Snapshot.parse(undo) is not None:
            print(f"Para deshacer: backtide rebobinar {undo}")
        elif undo is not None:
            _error("el servicio ha dado un punto para deshacer que no es válido: no se muestra")
        else:
            print("No se ha podido guardar un punto para deshacer.", file=sys.stderr)
        print(agent_line)
    return code


@contextmanager
def _shielded_from_stop_signals() -> Iterator[None]:
    """Ctrl-C, SIGTERM and SIGHUP are ignored while this process rewinds on its own: a rewind
    cut in the middle would leave the agent stopped and the workspace half swapped. (A service
    is shielded by being another process; SIGKILL still can, and the next start reconciles it.)
    Only the main thread can change handlers: elsewhere nothing is shielded."""
    numbers = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    try:
        previous = {number: signal.signal(number, signal.SIG_IGN) for number in numbers}
    except ValueError:
        yield
        return
    print("Rebobinando: Ctrl-C se ignora hasta terminar, para no dejarlo a medias.", flush=True)
    try:
        yield
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


class _SafeFormatter(logging.Formatter):
    """Log lines for the person's terminal: redacted, and with control characters escaped. A
    log message can quote what the agent wrote (a Docker error, a path)."""

    def format(self, record: logging.LogRecord) -> str:
        return _printable(redact(super().format(record)))


def _snapshot_lines(
    snapshots: list[Snapshot], *, now: datetime, tz: tzinfo, limit: int | None
) -> list[str]:
    """The table of `backtide instantaneas`: newest first, local time, the reason in Spanish and
    how long ago. ``snapshots`` come oldest first, like the store lists them."""
    if not snapshots:
        return ["No hay instantáneas todavía."]
    newest_first = list(reversed(snapshots))
    shown = newest_first if limit is None else newest_first[:limit]
    rows = [
        (
            snap.id,
            snap.taken_at.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S"),
            _printable(REASON_NAMES.get(snap.reason, snap.reason)),
            ago(now - snap.taken_at),
        )
        for snap in shown
    ]
    header = ("INSTANTÁNEA", "HORA", "MOTIVO", "HACE")
    widths = [max(len(row[column]) for row in [header, *rows]) for column in range(3)]
    lines = [
        "  ".join(cell.ljust(width) for cell, width in zip(row[:3], widths, strict=True))
        + "  "
        + row[3]
        for row in [header, *rows]
    ]
    hidden = len(newest_first) - len(shown)
    if hidden > 0:
        lines.append(f"… y {hidden} más (usa --todas para verlas todas)")
    return lines


def _now() -> datetime:
    return datetime.now(UTC)


def _local_tz() -> tzinfo:
    local = datetime.now().astimezone().tzinfo
    return local if local is not None else UTC


def _error(message: str) -> None:
    print(f"ERROR: {_printable(redact(message))}", file=sys.stderr)


def _print_report(report: VerifyReport) -> None:
    for warning in report.warnings:
        print(f"AVISO: {_describe(warning)}")
    if report.ok:
        last = report.last_seq if report.last_seq is not None else "ninguno"
        print(f"OK: {report.checked} eventos íntegros (último: {last})")
        return
    for problem in report.problems[:MAX_LISTED_PROBLEMS]:
        print(f"MANIPULADO: {_describe(problem)}")
    hidden = len(report.problems) - MAX_LISTED_PROBLEMS
    if hidden > 0:
        print(f"… y {hidden} problemas más")
    print(f"La caja negra NO está íntegra: {len(report.problems)} problemas.")


def _describe(problem: Problem) -> str:
    detail = _printable(problem.detail)
    if problem.seq is None:
        return detail
    return f"evento {problem.seq}: {detail}"


def _printable(text: str) -> str:
    """``text`` with control characters escaped. Details and errors can quote names an
    attacker chose (tables, triggers, paths), and escape sequences in them could rewrite
    what the terminal shows, for example turn MANIPULADO into a fake OK."""
    return "".join(char if char.isprintable() else repr(char)[1:-1] for char in text)


# -- `backtide web` (T12) -----------------------------------------------------------------------


def _add_web(commands: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    web = commands.add_parser(
        "web",
        help="abre el puesto de vigilancia en este ordenador",
        description="Sirve la web de backtide en 127.0.0.1 (solo este ordenador): lo que hace el "
        "agente en directo, la historia con filtros y las instantáneas. Solo lee la base de la "
        "caja negra (sin su clave ni el token) y se puede lanzar como un usuario sin privilegios "
        "con permiso de lectura sobre ella: así solo mira. Con --rebobinar y con el mismo usuario "
        "que el servicio, también rebobina, pidiéndoselo al servicio por su socket de control "
        "(con su aviso y una confirmación). Con --ajustes, igual, la página Ajustes pone, cambia "
        "y quita las claves de los modelos y el bot de Telegram (nunca las enseña). Con "
        "--aprobar, igual, aprueba y rechaza las peticiones retenidas por la puerta (con una "
        "confirmación). Con --socket-web, todo eso lo pide por el socket estrecho que el servicio "
        "abre para el grupo de la web, sin ser su usuario: así actúa la web instalada. Como root, "
        "sin --rebobinar, --ajustes ni --aprobar no arranca. Imprime un "
        "enlace de un solo uso, nuevo en cada ejecución, y el nombre de la ejecución; ábrelo en "
        "el navegador (no abre nada por sí mismo). Ctrl-C la para. Sale con 0 si paró bien, 1 si "
        "no pudo arrancar y 2 si la configuración no sirve.",
    )
    _add_config(web)
    web.add_argument(
        "--puerto",
        "--port",
        dest="port",
        type=int,
        default=None,
        help="puerto en 127.0.0.1 (por defecto 8765; 0 elige uno libre)",
    )
    web.add_argument(
        "--rebobinar",
        action="store_true",
        help="deja que la web pida rebobinados al servicio (hace falta su mismo usuario); sin "
        "esto, la web solo mira",
    )
    web.add_argument(
        "--ajustes",
        action="store_true",
        help="deja que la página Ajustes cambie las claves pidiéndoselo al servicio (hace falta su "
        "mismo usuario); sin esto, la página solo dice cómo encenderla",
    )
    web.add_argument(
        "--aprobar",
        action="store_true",
        help="deja que la web apruebe y rechace las peticiones retenidas pidiéndoselo al servicio "
        "(hace falta su mismo usuario); sin esto, las enseña con los botones apagados",
    )
    web.add_argument(
        "--socket-web",
        dest="web_socket",
        type=Path,
        metavar="RUTA",
        help="pide rebobinar, aprobar y los ajustes (cada uno con su opción) y la lista de "
        "instantáneas por el socket estrecho de la web (el de `backtide vigilar --grupo-web`), "
        "no por el socket de control: para una web que no corre con el usuario del servicio",
    )
    web.add_argument(
        "--enlace-en",
        dest="link_file",
        type=Path,
        metavar="ARCHIVO",
        help="escribe el enlace de un solo uso en ARCHIVO (0600) en vez de imprimirlo: lo usa "
        "backtide-web.service para que el enlace no quede en el registro (`sudo backtide "
        "enlace` lo enseña)",
    )
    web.set_defaults(handler=_web)

    link = commands.add_parser(
        "enlace",
        help="enseña el enlace de la web instalada (backtide-web.service)",
        description="Enseña el enlace de un solo uso de la web que corre como servicio "
        "(backtide-web.service), con el nombre de su ejecución y cómo llegar desde otro "
        "ordenador sin abrir puertos (`ssh -L`). Hace falta `sudo`: el enlace es un archivo de "
        "la web que nadie más puede leer, nunca una línea del registro. Para uno nuevo, "
        "`sudo systemctl restart backtide-web`. Sale con 0 si lo enseña y 1 si no hay.",
    )
    link.add_argument(
        "--archivo",
        dest="link_file",
        type=Path,
        default=layout.WEB_LINK_FILE,
        help=argparse.SUPPRESS,
    )
    link.set_defaults(handler=_link)


WEB_REWIND_LINES = {
    "ready": "Rebobinar desde la web: sí. Se lo pide al servicio por su socket (el de control, o "
    "el estrecho de la web con --socket-web), con el aviso y una confirmación.",
    "no_service": "Rebobinar desde la web: cuando el servicio esté en marcha (`backtide vigilar`).",
    "other_user": "Rebobinar desde la web: no. Esta web no corre con el usuario del servicio ni "
    "tiene el grupo de su socket estrecho, así que solo mira; para rebobinar, `backtide "
    "rebobinar`.",
    "off": "Rebobinar desde la web: no disponible; para rebobinar, `backtide rebobinar`.",
    "disabled": "Rebobinar desde la web: no; sin `--rebobinar` esta web solo mira. Para rebobinar, "
    "`backtide rebobinar` (o `backtide web --rebobinar` con el usuario del servicio).",
}
WEB_SETTINGS_LINES = {
    "ready": "Ajustes desde la web: sí. Las claves se ponen y se quitan pidiéndoselo al servicio "
    "(nunca se enseñan).",
    "no_service": "Ajustes desde la web: cuando el servicio esté en marcha (`backtide vigilar`).",
    "other_user": "Ajustes desde la web: no. Esta web no corre con el usuario del servicio.",
    "off": "Ajustes desde la web: no disponibles.",
    "disabled": "Ajustes desde la web: no; sin `--ajustes` la página solo dice cómo encenderla.",
}
WEB_APPROVE_LINES = {
    "ready": "Aprobar desde la web: sí. Las peticiones retenidas se aprueban y se rechazan "
    "pidiéndoselo al servicio (con una confirmación).",
    "no_service": "Aprobar desde la web: cuando el servicio esté en marcha (`backtide vigilar`).",
    "other_user": "Aprobar desde la web: no. Esta web no corre con el usuario del servicio; usa "
    "Telegram o `backtide aprobar`.",
    "off": "Aprobar desde la web: no disponible; usa Telegram o `backtide aprobar`.",
    "disabled": "Aprobar desde la web: no; sin `--aprobar` las peticiones retenidas se ven con "
    "los botones apagados. Usa Telegram o `backtide aprobar`.",
}
ROOT_WEB_REFUSAL = (
    "esta web iba a correr como root: con todos los privilegios y solo para mirar. Para mirar, "
    "lánzala con un usuario lector (con permiso de lectura sobre la caja negra); si de verdad "
    "quieres rebobinar, cambiar las claves o aprobar desde la web como root, pásale --rebobinar, "
    "--ajustes o --aprobar sabiendo lo que haces."
)


ROOT_WEB_WARNING = (
    "Ojo: esta web corre como root; para solo mirar, lánzala con un usuario lector (con permiso "
    "de lectura sobre la caja negra). Como root puede rebobinar, pero cualquier fallo suyo sería "
    "un fallo con todos los privilegios."
)


def _effective_uid() -> int:
    return os.geteuid()


def _web_rewind_line(availability: str) -> str:
    return WEB_REWIND_LINES.get(str(availability), WEB_REWIND_LINES["off"])


def _web(args: argparse.Namespace) -> int:
    from backtide.web.approve import ControlApprover
    from backtide.web.paths import WebPaths
    from backtide.web.rewind import ControlRewinder
    from backtide.web.server import DEFAULT_PORT, SERVICE_UID, run_web
    from backtide.web.settings import ControlSettings

    if _effective_uid() == 0 and not (args.rebobinar or args.ajustes or args.aprobar):
        _error(ROOT_WEB_REFUSAL)
        return EXIT_ERROR
    port = DEFAULT_PORT if args.port is None else args.port
    if not 0 <= port <= 65535:
        _error(f"el puerto debe estar entre 0 y 65535, no {port}")
        return EXIT_ERROR
    try:
        # Only the paths the web needs: never the gateway token, never the black box's key.
        paths = WebPaths.from_file(args.config)
    except ConfigError as error:
        _error(f"configuración no válida: {error}")
        return EXIT_ERROR
    web_socket = getattr(args, "web_socket", None)
    control, server_uid = paths.control_socket, None
    if web_socket is not None:
        control, server_uid = web_socket, SERVICE_UID

    def announce(url: str, run_name: str) -> None:
        if args.link_file is not None:
            try:
                _write_link(args.link_file, url, run_name)
            except OSError as error:
                raise LinkFileError(args.link_file, error) from None
            print(
                f"Puesto de vigilancia listo, solo en este ordenador. Ejecución: {run_name}. El "
                f"enlace de un solo uso está en {args.link_file}: `sudo backtide enlace` lo "
                "enseña.",
                flush=True,
            )
        else:
            print(f"Puesto de vigilancia listo, solo en este ordenador:\n\n  {url}\n", flush=True)
            print(
                f"Nombre de esta ejecución: {run_name}\n"
                "Debe ser el mismo que sale en la cabecera de la página: si no, no es esta.\n"
                "El enlace vale una sola vez (después la página usa una cookie de este "
                "navegador). Ctrl-C la para.",
                flush=True,
            )
        rewinder = ControlRewinder(control, enabled=args.rebobinar, server_uid=server_uid)
        print(_web_rewind_line(rewinder.availability()), flush=True)
        settings = ControlSettings(control, enabled=args.ajustes, server_uid=server_uid)
        line = WEB_SETTINGS_LINES.get(str(settings.availability()), WEB_SETTINGS_LINES["off"])
        print(line, flush=True)
        approver = ControlApprover(control, enabled=args.aprobar, server_uid=server_uid)
        line = WEB_APPROVE_LINES.get(str(approver.availability()), WEB_APPROVE_LINES["off"])
        print(line, flush=True)
        if _effective_uid() == 0:
            print(ROOT_WEB_WARNING, flush=True)

    try:
        run_web(
            paths,
            port,
            announce,
            can_rewind=args.rebobinar,
            can_set=args.ajustes,
            can_approve=args.aprobar,
            **({} if web_socket is None else {"web_socket": web_socket}),
        )
    except LinkFileError as error:
        _error(str(error))
        return EXIT_FAILED
    except OSError as error:
        _error(f"no se puede abrir el puerto {port} en 127.0.0.1: {error.strerror or error}")
        return EXIT_FAILED
    finally:
        if args.link_file is not None:
            _remove_link(args.link_file)
    print("Puesto de vigilancia parado.")
    return EXIT_OK


class LinkFileError(Exception):
    """The web could not write its link file (`--enlace-en`)."""

    def __init__(self, path: Path, error: OSError) -> None:
        super().__init__(
            f"no se puede escribir el enlace en {path}: {error.strerror or error}. La web no "
            "arranca sin poder dar su enlace."
        )


def _write_link(path: Path, url: str, run_name: str) -> None:
    """The link and the run's name, in a new 0600 file of ours (never through a link)."""
    _remove_link(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(path, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, f"{url}\n{run_name}\n".encode())
    finally:
        os.close(fd)


def _remove_link(path: Path) -> None:
    """A link that no longer opens anything is not left behind."""
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    except OSError as error:
        logger.warning("could not remove the web's link file %s: %s", path, error.strerror)


LINK_MAX_BYTES = 4096


def _link(args: argparse.Namespace) -> int:
    """`backtide enlace`: the installed web's one-time link, read from its file."""
    from backtide.web.server import web_url_problem

    path = args.link_file
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        _error(
            f"no hay enlace en {path}: ¿está en marcha la web (`systemctl status "
            f"{layout.WEB_UNIT}`)? Arráncala con `sudo systemctl start {layout.WEB_UNIT}`."
        )
        return EXIT_FAILED
    except PermissionError:
        _error("el enlace solo lo puede leer root: `sudo backtide enlace`.")
        return EXIT_FAILED
    except OSError as error:
        _error(f"no se puede abrir {path}: {error.strerror}")
        return EXIT_FAILED
    try:
        info = os.fstat(fd)
        data = os.read(fd, LINK_MAX_BYTES + 1) if stat.S_ISREG(info.st_mode) else b""
    finally:
        os.close(fd)
    lines = data.decode("utf-8", errors="replace").splitlines()
    if (
        len(data) > LINK_MAX_BYTES
        or len(lines) != 2
        or stat.S_IMODE(info.st_mode) & 0o077
        or web_url_problem(lines[0]) is not None
    ):
        _error(f"{path} no es el archivo del enlace de la web: no se enseña.")
        return EXIT_FAILED
    url, run_name = lines[0], _printable(lines[1])
    port = url.split(":")[2].split("/")[0]
    print(f"Puesto de vigilancia, solo en ese ordenador:\n\n  {url}\n")
    print(
        f"Nombre de esta ejecución: {run_name} (debe salir igual en la cabecera de la página).\n"
        "El enlace vale una sola vez; para uno nuevo, `sudo systemctl restart "
        f"{layout.WEB_UNIT}` y otra vez `sudo backtide enlace`.\n"
        f"Si backtide corre en otro ordenador, llega sin abrir ningún puerto: `ssh -L "
        f"{port}:127.0.0.1:{port} <usuario>@<servidor>` y abre el enlace en tu navegador."
    )
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
