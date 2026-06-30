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

"""Scan command parser and runtime handler."""

from __future__ import annotations

import argparse
import time
from typing import TYPE_CHECKING

from pysymex._internal.cli.commands.validation import (
    non_negative_float,
    non_negative_int,
    positive_int,
)
from pysymex._internal.cli.output import CliOutput
from pysymex._internal.config.defaults import (
    DEFAULT_PROFILE_MODE,
    DEFAULT_PROFILE_OUTPUT_DIR,
    DEFAULT_PROFILE_SAMPLE_INTERVAL_MS,
    DEFAULT_SCAN_MAX_DEPTH,
    DEFAULT_SCAN_MAX_ITERATIONS,
    DEFAULT_SCAN_MAX_PATHS,
    DEFAULT_SCAN_OUTPUT_FORMAT,
    DEFAULT_SCAN_TIMEOUT_SECONDS,
    DEFAULT_SCAN_WORKERS,
    DEFAULT_TRACE_OUTPUT_DIR,
    DEFAULT_TRACE_VERBOSITY,
    PROFILE_MODE_CHOICES,
    SCAN_OUTPUT_FORMAT_CHOICES,
    TRACE_VERBOSITY_CHOICES,
)
from pysymex._internal.logging.root import get_logger
from pysymex._internal.pathing import normalize_input_path

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from pysymex._internal.cli.commands.registry import Subparsers

_Namespace = argparse.Namespace
logger = get_logger(__name__)
_GLOB_CHARS = frozenset("*?[")


def add_scan_parser(subparsers: Subparsers) -> None:
    """Register the ``scan`` sub-command parser."""
    scan_parser = subparsers.add_parser(
        "scan",
        prog="pysymex scan",
        usage="pysymex scan [options] PATH",
        help="Scan files for supported runtime issues",
        description="Scan Python files or directories for supported symbolic-execution issues.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  pysymex scan path/to/file.py\n"
            "  pysymex scan src/ --format sarif -o report.sarif\n"
            '  pysymex scan "src/**/*.py" --format json'
        ),
    )
    scan_parser.add_argument("path", metavar="PATH", help="File, directory, or glob to scan")
    scan_parser.add_argument(
        "-f",
        "--function",
        metavar="NAME",
        help=(
            "Scan only one function or dotted method path. "
            "This avoids helper-function noise in adversarial files."
        ),
    )
    scan_parser.add_argument(
        "--format",
        choices=SCAN_OUTPUT_FORMAT_CHOICES,
        metavar="FORMAT",
        default=DEFAULT_SCAN_OUTPUT_FORMAT,
        help="Output format. Choices: text, json, sarif, rich, html, markdown (default: text)",
    )
    scan_parser.add_argument("-o", "--output", help="Write report to file")
    scan_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    scan_parser.add_argument(
        "--stats",
        action="store_true",
        help="Show detailed performance statistics (time, memory)",
    )
    scan_parser.add_argument(
        "--profile",
        action="store_true",
        help="Enable low-overhead developer profiling, stats, and bottleneck analysis",
    )
    scan_parser.add_argument(
        "--profile-mode",
        choices=PROFILE_MODE_CHOICES,
        default=DEFAULT_PROFILE_MODE,
        help=(
            "Profiler backend. sample = low-overhead statistical sampling; "
            "cprofile = deterministic call tracing (default: sample)"
        ),
    )
    scan_parser.add_argument(
        "--profile-sample-interval-ms",
        type=non_negative_float,
        default=DEFAULT_PROFILE_SAMPLE_INTERVAL_MS,
        help="Sampling interval for --profile-mode sample in milliseconds (default: 5.0)",
    )
    scan_parser.add_argument(
        "--profile-output-dir",
        default=DEFAULT_PROFILE_OUTPUT_DIR,
        help="Directory where --profile artifacts are written (default: .pysymex/profiles)",
    )
    scan_parser.add_argument(
        "--profile-baseline",
        metavar="PROFILE.json",
        help="Compare --profile metrics with a prior profile JSON artifact",
    )
    scan_parser.add_argument(
        "--max-paths",
        type=positive_int,
        default=DEFAULT_SCAN_MAX_PATHS,
        help="Optional maximum paths to explore (default: automatic)",
    )
    scan_parser.add_argument(
        "--max-depth",
        type=positive_int,
        default=DEFAULT_SCAN_MAX_DEPTH,
        help="Optional maximum symbolic step depth per path (default: automatic)",
    )
    scan_parser.add_argument(
        "--timeout",
        type=positive_int,
        default=DEFAULT_SCAN_TIMEOUT_SECONDS,
        help="Optional timeout per function in seconds (default: automatic)",
    )
    scan_parser.add_argument(
        "--workers",
        type=non_negative_int,
        default=DEFAULT_SCAN_WORKERS,
        help=(
            "Number of parallel worker processes. "
            "0 = conservative auto mode (caps to avoid memory spikes). "
            "1 = sequential (no subprocess overhead)."
        ),
    )
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
        "--detect-overflow",
        action="store_true",
        help=(
            "Enable explicit bounded-integer overflow checks. "
            "Python ints are unbounded, so this policy is off by default."
        ),
    )
    scan_parser.add_argument(
        "--max-iterations",
        type=positive_int,
        default=DEFAULT_SCAN_MAX_ITERATIONS,
        help="Optional maximum total iterations per function (default: automatic)",
    )
    scan_parser.add_argument(
        "--reproduce",
        action="store_true",
        help="Generate reproduction scripts for findings",
    )
    scan_parser.add_argument(
        "--visualize",
        action="store_true",
        help="Show real-time progress visualization",
    )

    scan_parser.add_argument(
        "--trace",
        action="store_true",
        help="Emit execution traces for symbolic scan runs",
    )
    scan_parser.add_argument(
        "--trace-output-dir",
        default=DEFAULT_TRACE_OUTPUT_DIR,
        help="Directory where trace JSONL files are written (default: .pysymex/traces)",
    )
    scan_parser.add_argument(
        "--trace-verbosity",
        choices=TRACE_VERBOSITY_CHOICES,
        metavar="LEVEL",
        default=DEFAULT_TRACE_VERBOSITY,
        help="Trace detail level. Choices: quiet, delta_only, full (default: delta_only)",
    )


def _path_has_glob(path: str) -> bool:
    """Return whether *path* contains shell glob metacharacters."""
    return any(char in path for char in _GLOB_CHARS)


def _split_glob_path(path: str) -> tuple[Path, str]:
    """Split a glob path into the concrete base directory and relative pattern."""
    parts = path.replace("\\", "/").split("/")
    for index, part in enumerate(parts):
        if _path_has_glob(part):
            base_text = "/".join(parts[:index]) or "."
            pattern = "/".join(parts[index:])
            return normalize_input_path(base_text), pattern
    return normalize_input_path(path), ""


def _resolve_scan_path(path_text: str) -> tuple[Path, str | None]:
    """Resolve a scan path, expanding literal glob arguments when the shell does not."""
    path = normalize_input_path(path_text)
    if path.exists() or not _path_has_glob(path_text):
        return path, None

    base_path, pattern = _split_glob_path(path_text)
    if not pattern or not base_path.is_dir():
        return path, None
    try:
        has_matches = any(base_path.glob(pattern))
    except (OSError, ValueError):
        return path, None
    if not has_matches:
        return path, None
    return base_path, pattern


def cmd_scan(args: _Namespace) -> int:
    """Execute the ``scan`` sub-command."""
    if getattr(args, "profile_baseline", None):
        args.profile = True
    if getattr(args, "profile", False):
        args.stats = True
    path, glob_pattern = _resolve_scan_path(str(args.path))
    if glob_pattern is not None:
        args._scan_glob_pattern = glob_pattern
    if not path.exists():
        logger.warning("Scan CLI path does not exist: %s", path)
        CliOutput.error(f"Path not found: {path}")
        return 1
    if args.verbose:
        pass
    stop_stats: Callable[[], None] | None = None
    if getattr(args, "stats", False):
        from pysymex._internal.stats.runtime import enable_console_sink, start, stop

        enable_console_sink()
        stop_stats = stop
        start()
    start_time = time.time()
    try:
        logger.verbose("Scan CLI starting symbolic scan for %s", path)
        return handle_symbolic_scan(args, path, start_time)
    finally:
        if stop_stats is not None and not getattr(args, "_stats_stopped", False):
            stop_stats()


def handle_symbolic_scan(args: _Namespace, path: Path, start_time: float) -> int:
    """Import and run the symbolic scan handler only when scan execution starts."""
    from pysymex._internal.cli.commands.scan.symbolic import (
        handle_symbolic_scan as run_symbolic_scan,
    )

    return run_symbolic_scan(args, path, start_time)


def run_scan_command(args: _Namespace) -> int:
    """Dispatch ``scan`` to the synchronous implementation."""
    return cmd_scan(args)
