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

"""Benchmark CLI command."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from pysymex._internal.cli.commands.validation import (
    non_negative_float,
    non_negative_int,
    positive_int,
)
from pysymex._internal.cli.output import CliOutput
from pysymex._internal.config.defaults import DEFAULT_BENCHMARK_ITERATIONS, DEFAULT_OUTPUT_FORMAT
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from pysymex._internal.benchmarks.suite.types import (
        BenchmarkEvent,
        BenchmarkResult,
        RegressionResult,
    )
    from pysymex._internal.cli.commands.registry import Subparsers

_Namespace = argparse.Namespace
logger = get_logger(__name__)


def add_benchmark_parser(subparsers: Subparsers) -> None:
    """Register the ``benchmark`` sub-command parser."""
    bench_parser = subparsers.add_parser(
        "benchmark",
        prog="pysymex benchmark",
        usage="pysymex benchmark [options]",
        help="Run built-in performance benchmarks",
        description="Run built-in benchmark cases and optional baseline comparisons.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  pysymex benchmark --list\n"
            "  pysymex benchmark --mode quick --format markdown -o benchmark.md\n"
            "  pysymex benchmark --category solving --iterations 3 --warmup 1"
        ),
    )
    bench_parser.add_argument(
        "--format",
        choices=("text", "json", "markdown"),
        metavar="FORMAT",
        default=DEFAULT_OUTPUT_FORMAT,
        help="Output format. Choices: text, json, markdown (default: text)",
    )
    bench_parser.add_argument(
        "--mode",
        choices=("quick", "full", "stress", "all"),
        metavar="MODE",
        default=None,
        help=(
            "Benchmark scope (default: quick for unfiltered runs, all modes for focused "
            "filters; choices: quick, full, stress, all)"
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
        metavar="CATEGORY",
        help=(
            "Run only one benchmark category. Choices: opcodes, paths, solving, analysis, "
            "end_to_end, memory, concurrency, models, reporting, sandbox, cli"
        ),
    )
    bench_parser.add_argument("-o", "--output", help="Write results to file")
    bench_parser.add_argument("--baseline", help="Compare against baseline file")
    bench_parser.add_argument(
        "-n",
        "--iterations",
        type=positive_int,
        default=DEFAULT_BENCHMARK_ITERATIONS,
        help=f"Iterations per benchmark (default: {DEFAULT_BENCHMARK_ITERATIONS})",
    )
    bench_parser.add_argument(
        "--warmup",
        type=non_negative_int,
        default=1,
        help="Warm-up iterations per benchmark (default: 1)",
    )
    bench_parser.add_argument("--case", type=str, help="Run a specific benchmark case by name")
    bench_parser.add_argument("--list", action="store_true", help="List benchmark cases and exit")
    bench_parser.add_argument(
        "--threshold",
        type=non_negative_float,
        default=10.0,
        help="Regression threshold percent when --baseline is used (default: 10.0)",
    )


def cmd_benchmark(args: _Namespace) -> int:
    """Execute the ``benchmark`` sub-command.

    Runs the built-in benchmark suite and writes results in the
    requested format.

    Args:
        args: Parsed CLI namespace with benchmark filtering and output options.

    Returns:
        ``0`` on success, ``1`` if regressions are detected.

    """
    from pysymex._internal.benchmarks.suite.reporting import BenchmarkReporter
    from pysymex._internal.benchmarks.suite.runner import run_benchmarks

    output_path = Path(args.output) if args.output else None
    baseline_path = Path(args.baseline) if args.baseline else None
    logger.verbose(
        "Benchmark command started output=%s baseline=%s format=%s iterations=%s",
        output_path,
        baseline_path,
        args.format,
        args.iterations,
    )
    try:
        progress_stream = sys.stderr if args.format in {"json", "markdown"} else sys.stdout

        def _print_progress(event: BenchmarkEvent) -> None:
            print(BenchmarkReporter.progress_line(event), file=progress_stream)

        run_result = run_benchmarks(
            baseline_path=baseline_path,
            iterations=args.iterations,
            case_name=getattr(args, "case", None),
            mode=getattr(args, "mode", None),
            category=getattr(args, "category", None),
            warmup=getattr(args, "warmup", 1),
            list_cases=getattr(args, "list", False),
            threshold_percent=getattr(args, "threshold", 10.0),
            progress=_print_progress,
        )
        if getattr(args, "list", False):
            CliOutput.emit(
                BenchmarkReporter.format_inventory(run_result.inventory),
                output_path=args.output,
                verbose=False,
            )
            return run_result.exit_code
        output = _format_benchmark_output(
            run_result.results,
            run_result.regressions,
            output_format=str(args.format),
            threshold_percent=float(getattr(args, "threshold", 10.0)),
        )
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(f"{output}\n", encoding="utf-8")
        else:
            CliOutput.emit(output, output_path=None, verbose=False)
        return run_result.exit_code
    except Exception as e:
        logger.warning("Benchmark command failed", exc_info=True)
        CliOutput.error(f"running benchmarks: {e}")
        return 1


def _format_benchmark_output(
    results: list[BenchmarkResult],
    regressions: list[RegressionResult],
    *,
    output_format: str,
    threshold_percent: float,
) -> str:
    from pysymex._internal.benchmarks.suite.comparison import BenchmarkComparator
    from pysymex._internal.benchmarks.suite.reporting import BenchmarkReporter

    if output_format == "json":
        return BenchmarkReporter.to_json(results)
    if output_format == "markdown":
        report = BenchmarkReporter.to_markdown(results)
    else:
        report = BenchmarkReporter.to_text(results)
    if regressions:
        comparison = BenchmarkComparator(threshold_percent=threshold_percent).report_regressions(
            regressions,
        )
        report = f"{report}\n\n{comparison}"
    return report
