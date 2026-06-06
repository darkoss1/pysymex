# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Argument parser creation for pysymex CLI."""

from __future__ import annotations

import argparse

from pysymex.cli.parser.commands import add_command_parsers


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser with subcommands."""
    parser = argparse.ArgumentParser(
        prog="pysymex",
        description=" pysymex - Symbolic Execution Engine for Python",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  pysymex scan path/to/file.py          Symbolic execution scan
  pysymex scan path/to/dir -r           Scan directory recursively
  pysymex analyze file.py -f func_name  Analyze specific function
  pysymex verify file.py                Verify function contracts
  pysymex benchmark                      Run benchmark suite
        """,
    )

    from pysymex.config import VERSION

    __version__ = VERSION

    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--generate-completion",
        choices=["bash", "zsh", "fish"],
        help="Generate shell completion script",
    )
    parser.add_argument("--quiet", action="store_true", help="Suppress non-error diagnostics")
    parser.add_argument("--debug", action="store_true", help="Enable debug diagnostics")
    parser.add_argument("--diagnostic-trace", action="store_true", help="Enable trace diagnostics")
    parser.add_argument(
        "--log-category",
        action="append",
        default=None,
        help="Enable a diagnostic category; can be passed multiple times",
    )
    parser.add_argument("--log-jsonl", help="Write structured diagnostics to a JSONL file")
    parser.add_argument(
        "--log-history",
        type=int,
        default=0,
        help="Retain a bounded in-memory diagnostic history for this run",
    )

    subparsers = parser.add_subparsers(dest="command", metavar="command")
    add_command_parsers(subparsers)
    return parser
