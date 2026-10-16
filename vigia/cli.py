"""Command-line entry point: `vigia`. Messages for the user are in Spanish."""

import argparse
import logging
import sys
from datetime import UTC, datetime, timedelta, tzinfo
from pathlib import Path

from vigia import __version__
from vigia.blackbox import BlackBox, BlackBoxError, Problem, VerifyReport, load_key
from vigia.jail import JailError
from vigia.jail.openclaw import UnrewindableConfig
from vigia.service.config import ConfigError, ServiceConfig
from vigia.service.runner import ServiceLocked, serve
from vigia.snapshots import Snapshot, SnapshotError, SnapshotStore

logger = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_TAMPERED = 1  # verificar: the black box is not intact
EXIT_FAILED = 1  # vigilar: the service could not run, or could not stop the agent
EXIT_ERROR = 2  # usage errors (argparse also exits with 2) and unreadable inputs
NOT_VERIFIED = "NO VERIFICADA: trátala como no íntegra"
MAX_LISTED_PROBLEMS = 50
DEFAULT_CONFIG = Path("/etc/vigia/vigia.toml")
DEFAULT_LISTED_SNAPSHOTS = 30  # docs/19, decision 21
REASON_NAMES = {
    "periodic": "periódica",
    "manual": "manual",
    "pre_restore": "antes de rebobinar",
    "recovered": "recuperada",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vigia",
        description="Black box for AI agents: record, rewind and stop the irreversible.",
    )
    parser.add_argument("--version", action="version", version=f"vigia {__version__}")
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
        description="Arranca a Vigía en primer plano: graba al agente, hace instantáneas de su "
        "carpeta cuando cambia algo y lo para si Vigía se para. Ctrl-C o SIGTERM paran a Vigía y, "
        "con él, al agente. Sale con 0 si paró bien, 1 si no pudo arrancar o no pudo parar al "
        "agente y 2 si la configuración no sirve.",
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
    return parser


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
    print("Vigía arrancando. Ctrl-C o SIGTERM lo paran, y con él al agente.", flush=True)
    try:
        serve(config)
    except UnrewindableConfig as error:
        _error(error.notice)  # the alert and the black box already hold the detail
        return EXIT_ERROR
    except ServiceLocked as error:
        _error(str(error))
        return EXIT_FAILED
    except BlackBoxError as error:
        _error(f"no se puede usar la caja negra, así que Vigía no vigila: {error}")
        for note in getattr(error, "__notes__", []):
            _error(note)
        return EXIT_FAILED
    except JailError as error:
        _error(f"EL AGENTE SIGUE EN MARCHA y Vigía no ha podido pararlo: {error}")
        return EXIT_FAILED
    except Exception as error:  # nothing on this path is swallowed: it is logged with its trace
        logger.exception("vigia vigilar failed")
        _error(f"error inesperado, Vigía se ha parado: {type(error).__name__}: {error}")
        _error(
            "No se sabe si el agente sigue en marcha. Compruébalo con "
            f"`docker ps --filter name={config.jail_config().name}` y, si aparece, páralo con "
            f"`docker stop {config.jail_config().name}`."
        )
        return EXIT_FAILED
    print("Vigía parado. El agente está parado.")
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


def _snapshot_lines(
    snapshots: list[Snapshot], *, now: datetime, tz: tzinfo, limit: int | None
) -> list[str]:
    """The table of `vigia instantaneas`: newest first, local time, the reason in Spanish and
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
            _age(now - snap.taken_at),
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


def _age(elapsed: timedelta) -> str:
    seconds = elapsed.total_seconds()
    if seconds < -5:
        return "en el futuro (¿reloj mal?)"
    if seconds < 60:
        return "hace unos segundos"
    if seconds < 3600:
        return f"hace {int(seconds // 60)} min"
    if seconds < 48 * 3600:
        return f"hace {int(seconds // 3600)} h"
    return f"hace {int(seconds // 86400)} días"


def _now() -> datetime:
    return datetime.now(UTC)


def _local_tz() -> tzinfo:
    local = datetime.now().astimezone().tzinfo
    return local if local is not None else UTC


def _error(message: str) -> None:
    print(f"ERROR: {_printable(message)}", file=sys.stderr)


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


if __name__ == "__main__":
    raise SystemExit(main())
