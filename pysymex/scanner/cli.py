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

"""Command-line interface (CLI) entry point for the scanner.

This module parses command-line arguments to scan folders recursively,
run parallel or sequential code analysis passes, and write JSON logs.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from pysymex.analysis.detectors.protocols import ScanReporter
from pysymex.cli.reporter import ConsoleScanReporter
from pysymex.config.defaults import (
    DEFAULT_SCANNER_CLI_DIRECTORY,
    DEFAULT_SCANNER_CLI_MAX_ITERATIONS,
    DEFAULT_SCANNER_CLI_RECURSIVE,
    DEFAULT_SCANNER_CLI_WORKERS,
    DEFAULT_SCANNER_DIRECTORY_MAX_PATHS,
    DEFAULT_SCANNER_TIMEOUT_SECONDS,
)
from pysymex.logger import get_logger
from pysymex.scanner.directory import scan_directory
from pysymex.scanner.session import session_var
from pysymex.scanner.summary import print_final_summary
from pysymex.scanner.types import ScanSession

logger = get_logger(__name__)


def main() -> None:
    """Execute the command-line scanner orchestration flow.

    Parses configuration flags, sets up a new :class:`~pysymex.scanner.types.ScanSession`,
    locates all target Python source files under the configured root directory,
    initiates parallel or sequential analysis, and prints summary metrics.

    Side Effects:
        - Modifies the thread-local :class:`~pysymex.scanner.session.session_var`.
        - Emits events and progress status to the :class:`~pysymex.cli.reporter.ConsoleScanReporter`.
        - Saves a JSON session log file to disk.

    Raises:
        SystemExit: With exit code ``1`` if the scanned directory does not exist.
    """
    reporter: ScanReporter = ConsoleScanReporter()

    parser = argparse.ArgumentParser(description="pysymex Scanner")
    parser.add_argument(
        "--dir",
        "-d",
        type=str,
        default=DEFAULT_SCANNER_CLI_DIRECTORY,
        help="Directory to scan (default: current directory)",
    )
    parser.add_argument(
        "--log",
        "-l",
        type=str,
        default=None,
        help="Log file path (default: scan_log_TIMESTAMP.json)",
    )
    parser.add_argument(
        "--recursive",
        "-r",
        action="store_true",
        default=DEFAULT_SCANNER_CLI_RECURSIVE,
        help="Scan subdirectories recursively (default: True)",
    )
    parser.add_argument(
        "--auto-tune",
        "-at",
        action="store_true",
        help="Automatically tune execution parameters based on code complexity",
    )
    parser.add_argument(
        "--max-paths",
        type=int,
        default=DEFAULT_SCANNER_DIRECTORY_MAX_PATHS,
        help="Maximum paths to explore (default: 200)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_SCANNER_TIMEOUT_SECONDS,
        help="Timeout per file in seconds (default: 30.0)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_SCANNER_CLI_WORKERS,
        help="Number of worker processes (0=auto)",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable process-local, result, and solver caches for fresh analysis",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=DEFAULT_SCANNER_CLI_MAX_ITERATIONS,
        help="Maximum iterations per function",
    )
    parser.add_argument(
        "--trace",
        action="store_true",
        help="Enable detailed execution tracing (generates JSONL logs)",
    )
    args = parser.parse_args()
    scan_dir = Path(args.dir)
    log_file = Path(args.log) if args.log else None
    if not scan_dir.exists():
        logger.warning("Scanner CLI directory does not exist: %s", scan_dir)
        reporter.on_error(scan_dir, f"Directory '{scan_dir}' does not exist")
        sys.exit(1)
    session = ScanSession(log_file=log_file)
    session_var.set(session)
    pattern = "**/*.py" if args.recursive else "*.py"
    existing_files = list(scan_dir.glob(pattern))
    if existing_files:
        logger.verbose(
            "Scanner CLI starting directory scan for %s files under %s",
            len(existing_files),
            scan_dir,
        )
        results = scan_directory(
            scan_dir,
            pattern=pattern,
            max_paths=args.max_paths,
            timeout=args.timeout,
            workers=args.workers,
            auto_tune=args.auto_tune,
            reporter=reporter,
            no_cache=args.no_cache,
            max_iterations=args.max_iterations,
            trace_enabled=args.trace,
        )
        if session:
            recorded_result_ids = {id(result) for result in session.results}
            for r in results:
                if id(r) in recorded_result_ids:
                    continue
                session.add_result(r)
                recorded_result_ids.add(id(r))
    else:
        logger.warning("Scanner CLI found no Python files under %s", scan_dir)
        reporter.on_status(f"No Python files found in {scan_dir}")
    print_final_summary(reporter=reporter)
    reporter.on_status("\nDone.")
