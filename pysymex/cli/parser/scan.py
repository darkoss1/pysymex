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

"""Scan subcommand parser registration."""

from __future__ import annotations

from typing import Any

from pysymex.config.defaults import (
    DEFAULT_SCAN_MAX_ITERATIONS,
    DEFAULT_SCAN_MAX_PATHS,
    DEFAULT_SCAN_OUTPUT_FORMAT,
    DEFAULT_SCAN_RANDOM_SEED,
    DEFAULT_SCAN_TIMEOUT_SECONDS,
    DEFAULT_SCAN_WORKERS,
    DEFAULT_TRACE_OUTPUT_DIR,
    DEFAULT_TRACE_VERBOSITY,
    SCAN_OUTPUT_FORMAT_CHOICES,
    TRACE_VERBOSITY_CHOICES,
)


def add_scan_parser(subparsers: Any) -> None:
    """Register arguments and options for the 'scan' subcommand.

    Args:
        subparsers (Any): The argparse subparsers action object.
    """
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan file or directory",
        description="Scan Python code for bugs and vulnerabilities",
    )
    scan_parser.add_argument("path", help="File or directory to scan")
    scan_parser.add_argument(
        "--format",
        choices=SCAN_OUTPUT_FORMAT_CHOICES,
        default=DEFAULT_SCAN_OUTPUT_FORMAT,
        help="Output format (default: text)",
    )
    scan_parser.add_argument("-o", "--output", help="Write report to file")
    scan_parser.add_argument(
        "-r", "--recursive", action="store_true", help="Scan directories recursively"
    )
    scan_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    scan_parser.add_argument(
        "--stats",
        action="store_true",
        help="Show detailed performance statistics (time, memory)",
    )
    scan_parser.add_argument(
        "--max-paths",
        type=int,
        default=DEFAULT_SCAN_MAX_PATHS,
        help="Maximum paths to explore (default: 5000)",
    )
    scan_parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_SCAN_TIMEOUT_SECONDS,
        help=f"Timeout per function in seconds (default: {DEFAULT_SCAN_TIMEOUT_SECONDS})",
    )
    scan_parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_SCAN_WORKERS,
        help=(
            "Number of parallel worker processes. "
            "0 = conservative auto mode (caps to avoid memory spikes). "
            "1 = sequential (no subprocess overhead)."
        ),
    )
    scan_parser.add_argument("--auto", action="store_true", help="Auto-tune analysis configuration")
    scan_parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable process-local, result, and solver caches for fresh analysis",
    )
    scan_parser.add_argument(
        "--no-sandbox",
        action="store_true",
        help="Compile target bytecode in-process instead of using sandboxed extraction",
    )
    scan_parser.add_argument(
        "--max-iterations",
        type=int,
        default=DEFAULT_SCAN_MAX_ITERATIONS,
        help="Maximum total iterations per function (0 = auto-calculate)",
    )
    scan_parser.add_argument(
        "--reproduce", action="store_true", help="Generate reproduction scripts for findings"
    )
    scan_parser.add_argument(
        "--visualize", action="store_true", help="Show real-time progress visualization"
    )
    scan_parser.add_argument(
        "--async",
        dest="use_async",
        action="store_true",
        help="Use async scanner with TaskGroup-based structured concurrency",
    )
    scan_parser.add_argument(
        "--trace", action="store_true", help="Emit execution traces for symbolic scan runs"
    )
    scan_parser.add_argument(
        "--trace-output-dir",
        default=DEFAULT_TRACE_OUTPUT_DIR,
        help="Directory where trace JSONL files are written (default: .pysymex/traces)",
    )
    scan_parser.add_argument(
        "--trace-verbosity",
        choices=TRACE_VERBOSITY_CHOICES,
        default=DEFAULT_TRACE_VERBOSITY,
        help="Trace detail level (default: delta_only)",
    )
    scan_parser.add_argument(
        "--deterministic",
        action="store_true",
        help="Use deterministic non-dynamic exploration for reproducible runs",
    )
    scan_parser.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_SCAN_RANDOM_SEED,
        help="Random seed for deterministic runs (default: 42)",
    )


__all__ = ["add_scan_parser"]
