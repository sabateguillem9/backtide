"""Command-line entry point: `vigia`."""

import argparse

from vigia import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vigia",
        description="Black box for AI agents: record, rewind and stop the irreversible.",
    )
    parser.add_argument("--version", action="version", version=f"vigia {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    parser.parse_args(argv)
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
