"""Command-line entry point: `vigia`. Messages for the user are in Spanish."""

import argparse
import sys
from pathlib import Path

from vigia import __version__
from vigia.blackbox import BlackBox, BlackBoxError, Problem, VerifyReport, load_key

EXIT_OK = 0
EXIT_TAMPERED = 1
EXIT_ERROR = 2  # usage errors (argparse also exits with 2) and unreadable inputs
NOT_VERIFIED = "NO VERIFICADA: trátala como no íntegra"
MAX_LISTED_PROBLEMS = 50


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
    return parser


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
