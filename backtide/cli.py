"""Command-line entry point: `backtide`. Messages for the user are in Spanish."""

import argparse
import logging
import os
import signal
import sys
import textwrap
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, tzinfo
from pathlib import Path

from backtide import __version__
from backtide.blackbox import BlackBox, BlackBoxError, Problem, VerifyReport, load_key, redact
from backtide.jail import ExposedJail, JailError
from backtide.jail.openclaw import UnrewindableConfig
from backtide.service.config import ConfigError, ServiceConfig
from backtide.service.control import (
    OUTCOME_EXIT_CODES,
    ControlError,
    ControlOutcomeUnknown,
    ControlUnavailable,
    ask_rewind,
)
from backtide.service.guardian import BOOT_STOP_FAILED_NOTE
from backtide.service.notice import ago, rewind_notice
from backtide.service.offline import rewind_without_service
from backtide.service.retenidas import decide as decide_hold
from backtide.service.retenidas import listing as list_holds
from backtide.service.runner import ServiceLocked, ServiceRunning, serve, take_lock
from backtide.service.seguir import seguir
from backtide.snapshots import Snapshot, SnapshotError, SnapshotStore

logger = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_TAMPERED = 1  # verificar: the black box is not intact
EXIT_FAILED = 1  # vigilar: the service could not run, or could not stop the agent
EXIT_ERROR = 2  # usage errors (argparse also exits with 2) and unreadable inputs
EXIT_PROBLEM = 3  # rebobinar: rewound, but something went wrong afterwards (or cannot tell)
NOT_VERIFIED = "NO VERIFICADA: trátala como no íntegra"
MAX_LISTED_PROBLEMS = 50
DEFAULT_CONFIG = Path("/etc/backtide/backtide.toml")
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
    _add_web(commands)
    return parser


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
    print("backtide arrancando. Ctrl-C o SIGTERM lo paran, y con él al agente.", flush=True)
    try:
        serve(config)
    except UnrewindableConfig as error:
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

    print(_rewind_notice(target, now=_now(), tz=_local_tz()))
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


def _rewind_notice(target: Snapshot, *, now: datetime, tz: tzinfo) -> str:
    paragraphs = (*rewind_notice(target.taken_at, now=now, tz=tz), REWIND_NOTICE_WITHOUT_SERVICE)
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
        "confirmación). Como root, sin --rebobinar, --ajustes ni --aprobar no arranca. "
        "Imprime un "
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
    web.set_defaults(handler=_web)


WEB_REWIND_LINES = {
    "ready": "Rebobinar desde la web: sí. Esta web corre con el mismo usuario que el servicio y se "
    "lo pide por su socket de control (con el aviso y una confirmación).",
    "no_service": "Rebobinar desde la web: cuando el servicio esté en marcha (`backtide vigilar`).",
    "other_user": "Rebobinar desde la web: no. Esta web no corre con el usuario del servicio, así "
    "que solo mira; para rebobinar, `backtide rebobinar`.",
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
    from backtide.web.server import DEFAULT_PORT, run_web
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

    def announce(url: str, run_name: str) -> None:
        print(f"Puesto de vigilancia listo, solo en este ordenador:\n\n  {url}\n", flush=True)
        print(
            f"Nombre de esta ejecución: {run_name}\n"
            "Debe ser el mismo que sale en la cabecera de la página: si no, no es esta.\n"
            "El enlace vale una sola vez (después la página usa una cookie de este navegador). "
            "Ctrl-C la para.",
            flush=True,
        )
        rewinder = ControlRewinder(paths.control_socket, enabled=args.rebobinar)
        print(_web_rewind_line(rewinder.availability()), flush=True)
        settings = ControlSettings(paths.control_socket, enabled=args.ajustes)
        line = WEB_SETTINGS_LINES.get(str(settings.availability()), WEB_SETTINGS_LINES["off"])
        print(line, flush=True)
        approver = ControlApprover(paths.control_socket, enabled=args.aprobar)
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
        )
    except OSError as error:
        _error(f"no se puede abrir el puerto {port} en 127.0.0.1: {error.strerror or error}")
        return EXIT_FAILED
    print("Puesto de vigilancia parado.")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
