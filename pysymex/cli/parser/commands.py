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

"""Subcommand registration for the pysymex CLI parser."""

from __future__ import annotations

from typing import Any

from pysymex.cli.parser.scan import add_scan_parser
from pysymex.config.defaults import (
    DEFAULT_ANALYZE_MAX_PATHS,
    DEFAULT_ANALYZE_TIMEOUT_SECONDS,
    DEFAULT_BENCHMARK_ITERATIONS,
    DEFAULT_CHECK_FAIL_ON,
    DEFAULT_OUTPUT_FORMAT,
    SCAN_OUTPUT_FORMAT_CHOICES,
)


def add_analyze_parser(subparsers: Any) -> None:
    """Register arguments and options for the 'analyze' subcommand.

    Args:
        subparsers (Any): The argparse subparsers action object.
    """
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze specific function",
        description="Perform symbolic execution on a specific function",
    )
    analyze_parser.add_argument("file", help="Python file to analyze")
    analyze_parser.add_argument("-f", "--function", required=True, help="Function to analyze")
    analyze_parser.add_argument("--args", nargs="*", help="Symbolic arguments (name:type)")
    analyze_parser.add_argument(
        "--format",
        choices=SCAN_OUTPUT_FORMAT_CHOICES,
        default=DEFAULT_OUTPUT_FORMAT,
        help="Output format (default: text)",
    )
    analyze_parser.add_argument("-o", "--output", help="Write report to file")
    analyze_parser.add_argument(
        "--max-paths",
        type=int,
        default=DEFAULT_ANALYZE_MAX_PATHS,
        help="Maximum execution paths to explore (default: 100000)",
    )
    analyze_parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_ANALYZE_TIMEOUT_SECONDS,
        help="Maximum analysis time in seconds (default: 60)",
    )
    analyze_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    analyze_parser.add_argument(
        "--stats",
        action="store_true",
        help="Show detailed performance statistics (time, memory)",
    )


def add_verify_parser(subparsers: Any) -> None:
    """Register arguments and options for the 'verify' subcommand.

    Args:
        subparsers (Any): The argparse subparsers action object.
    """
    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify function contracts",
        description="Verify function pre/postconditions and invariants",
    )
    verify_parser.add_argument("file", help="Python file with contracts")
    verify_parser.add_argument(
        "-f", "--function", help="Specific function to verify (default: all with contracts)"
    )
    verify_parser.add_argument("--args", nargs="*", help="Symbolic arguments (name:type)")
    verify_parser.add_argument(
        "--format",
        choices=SCAN_OUTPUT_FORMAT_CHOICES,
        default=DEFAULT_OUTPUT_FORMAT,
        help="Output format (default: text)",
    )
    verify_parser.add_argument("-o", "--output", help="Write report to file")
    verify_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")


def add_bench_parser(subparsers: Any) -> None:
    """Register arguments and options for the 'benchmark' subcommand.

    Args:
        subparsers (Any): The argparse subparsers action object.
    """
    bench_parser = subparsers.add_parser(
        "benchmark",
        help="Run benchmark suite",
        description="Run performance benchmarks",
    )
    bench_parser.add_argument(
        "--format",
        choices=("text", "json", "markdown"),
        default=DEFAULT_OUTPUT_FORMAT,
        help="Output format (default: text)",
    )
    bench_parser.add_argument(
        "--mode",
        choices=("quick", "full", "stress", "all"),
        default=None,
        help=(
            "Benchmark scope (default: quick for unfiltered runs, all modes for focused "
            "filters; use all to run every registered case)"
        ),
    )
    bench_parser.add_argument(
        "--category",
        choices=(
            "opcodes",
            "paths",
            "solving",
            "analysis",
            "end_to_end",
            "memory",
            "concurrency",
            "models",
            "reporting",
            "sandbox",
            "cli",
        ),
        help="Run only one benchmark category",
    )
    bench_parser.add_argument("-o", "--output", help="Write results to file")
    bench_parser.add_argument("--baseline", help="Compare against baseline file")
    bench_parser.add_argument(
        "-n",
        "--iterations",
        type=int,
        default=DEFAULT_BENCHMARK_ITERATIONS,
        help=f"Iterations per benchmark (default: {DEFAULT_BENCHMARK_ITERATIONS})",
    )
    bench_parser.add_argument(
        "--warmup",
        type=int,
        default=1,
        help="Warm-up iterations per benchmark (default: 1)",
    )
    bench_parser.add_argument("--case", type=str, help="Run a specific benchmark case by name")
    bench_parser.add_argument("--list", action="store_true", help="List benchmark cases and exit")
    bench_parser.add_argument(
        "--threshold",
        type=float,
        default=10.0,
        help="Regression threshold percent when --baseline is used (default: 10.0)",
    )


def add_check_parser(subparsers: Any) -> None:
    """Register arguments and options for the 'check' subcommand.

    Args:
        subparsers (Any): The argparse subparsers action object.
    """
    check_parser = subparsers.add_parser(
        "check",
        help="Run CI-friendly check (exit code reflects severity)",
        description="Run pysymex analysis suitable for CI/CD pipelines",
    )
    check_parser.add_argument("paths", nargs="+", help="Python files or directories to check")
    check_parser.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical"],
        default=DEFAULT_CHECK_FAIL_ON,
        help="Minimum severity to cause a non-zero exit (default: high)",
    )
    check_parser.add_argument("--sarif", type=str, help="Path to write SARIF report")
    check_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")


def add_command_parsers(subparsers: Any) -> None:
    """Register all subcommand parsers with the main CLI subparsers collection.

    Args:
        subparsers (Any): The argparse subparsers action object to add parsers to.
    """
    add_scan_parser(subparsers)
    add_analyze_parser(subparsers)
    add_verify_parser(subparsers)
    add_bench_parser(subparsers)
    add_check_parser(subparsers)


__all__ = [
    "add_analyze_parser",
    "add_bench_parser",
    "add_check_parser",
    "add_command_parsers",
    "add_scan_parser",
    "add_verify_parser",
]
