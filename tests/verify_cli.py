"""Entrypoint for the dedicated ``pysymex-verify`` console script."""

from __future__ import annotations

import sys

from pysymex.cli import main as _cli_main


def main(argv: list[str] | None = None) -> int:
    """Run the main CLI with the ``verify`` subcommand preselected."""
    args = list(argv) if argv is not None else sys.argv[1:]
    return _cli_main(["verify", *args])


if __name__ == "__main__":
    sys.exit(main())
