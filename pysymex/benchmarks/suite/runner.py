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

"""Benchmark suite runner used by the CLI and tests."""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import cast

from pysymex.benchmarks.suite.comparison import BenchmarkComparator
from pysymex.benchmarks.suite.reporting import BenchmarkReporter
from pysymex.benchmarks.suite.types import (
    BenchmarkCategory,
    BenchmarkEvent,
    BenchmarkMode,
    BenchmarkResult,
    BenchmarkStatus,
)
from pysymex.benchmarks.suite.workload.registry import create_builtin_benchmarks
from pysymex.logger import get_logger

logger = get_logger(__name__)
ProgressCallback = Callable[[BenchmarkEvent], None]


def run_benchmarks(
    output_path: Path | None = None,
    baseline_path: Path | None = None,
    format: str = "console",
    iterations: int = 5,
    case_name: str | None = None,
    mode: str | None = None,
    category: str | None = None,
    warmup: int = 1,
    list_cases: bool = False,
    threshold_percent: float = 10.0,
) -> int:
    """Run the built-in benchmarks from the CLI.

    Args:
        output_path: Optional file path for benchmark output.
        baseline_path: Optional baseline JSON for regression comparison.
        format: Output format (``console``, ``json``, ``markdown``).
        iterations: Number of timing iterations per benchmark.
        mode: Optional benchmark mode: ``quick``, ``full``, ``stress``, or ``all``.
        category: Optional category filter.
        warmup: Number of warm-up iterations per benchmark.
        list_cases: Print benchmark inventory without running cases.
        threshold_percent: Regression threshold when comparing to a baseline.

    Returns:
        ``0`` on success, ``1`` if regressions are detected.
    """
    suite = create_builtin_benchmarks()
    requested_all_modes = mode == "all"
    requested_mode = _parse_mode(mode)
    benchmark_mode = requested_mode
    if (
        not requested_all_modes
        and benchmark_mode is None
        and category is None
        and case_name is None
    ):
        benchmark_mode = BenchmarkMode.QUICK
    benchmark_category = _parse_category(category)
    selected = suite.select(
        mode=benchmark_mode,
        case_name=case_name,
        category=benchmark_category,
    )
    if list_cases:
        print(BenchmarkReporter.format_inventory([benchmark.name for benchmark in selected]))
        return 0

    logger.verbose(
        "Running benchmarks mode=%s category=%s iterations=%d warmup=%d case=%s format=%s",
        benchmark_mode.value if benchmark_mode is not None else "all",
        benchmark_category.name if benchmark_category else None,
        iterations,
        warmup,
        case_name,
        format,
    )
    progress: ProgressCallback | None = None
    if format in {"console", "text"}:
        progress = BenchmarkReporter.print_progress
    elif format in {"json", "markdown"}:
        progress = _stderr_progress

    results = suite.run_all(
        iterations=iterations,
        case_name=case_name,
        warmup=warmup,
        mode=benchmark_mode,
        category=benchmark_category,
        progress=progress,
    )
    if output_path:
        BenchmarkReporter.to_file(results, output_path, output_format=format)
    if format == "json":
        print(BenchmarkReporter.to_json(results))
    elif format == "markdown":
        print(BenchmarkReporter.to_markdown(results))
    else:
        BenchmarkReporter.to_console(results)

    if baseline_path and baseline_path.exists():
        logger.verbose("Loading benchmark baseline from %s", baseline_path)
        baseline_data: object = json.loads(baseline_path.read_text(encoding="utf-8"))
        baseline_items = (
            cast("list[object]", baseline_data) if isinstance(baseline_data, list) else []
        )
        name_aliases = {
            alias: benchmark.name for benchmark in suite.benchmarks for alias in benchmark.aliases
        }
        baseline = [
            _result_from_json(cast("dict[object, object]", item), name_aliases)
            for item in baseline_items
            if isinstance(item, dict)
        ]
        comparator = BenchmarkComparator(threshold_percent=threshold_percent)
        regressions = comparator.compare(baseline, results)
        print(comparator.report_regressions(regressions))
        if any(r.is_regression for r in regressions):
            logger.warning("Benchmark regression detected against %s", baseline_path)
            return 1
    if any(result.status is BenchmarkStatus.FAILED for result in results):
        return 1
    return 0


def _parse_mode(raw_mode: str | None) -> BenchmarkMode | None:
    """Parse a CLI mode string into a benchmark mode."""
    if raw_mode is None:
        return None
    if raw_mode == "all":
        return None
    try:
        return BenchmarkMode(raw_mode)
    except ValueError as exc:
        expected = ", ".join((*[mode.value for mode in BenchmarkMode], "all"))
        raise ValueError(
            f"unknown benchmark mode {raw_mode!r}; expected one of: {expected}"
        ) from exc


def _parse_category(raw_category: str | None) -> BenchmarkCategory | None:
    """Parse an optional CLI category filter."""
    if raw_category is None:
        return None
    try:
        return BenchmarkCategory[raw_category.upper()]
    except KeyError as exc:
        expected = ", ".join(category.name.lower() for category in BenchmarkCategory)
        raise ValueError(
            f"unknown benchmark category {raw_category!r}; expected one of: {expected}"
        ) from exc


def _stderr_progress(event: BenchmarkEvent) -> None:
    """Emit progress to stderr for machine-readable stdout formats."""
    BenchmarkReporter.print_progress(event, stream=sys.stderr)


def _float_field(data: dict[object, object], key: str) -> float:
    """Return a numeric JSON field as float for baseline comparison."""
    value = data.get(key, 0.0)
    if isinstance(value, bool):
        return 0.0
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return 0.0
    return 0.0


def _result_from_json(
    data: dict[object, object],
    name_aliases: dict[str, str] | None = None,
) -> BenchmarkResult:
    """Load the subset of result fields needed for regression comparison."""
    name = data.get("name", "")
    result_name = name if isinstance(name, str) else ""
    if name_aliases is not None:
        result_name = name_aliases.get(result_name, result_name)
    category = data.get("category", "END_TO_END")
    category_value = (
        BenchmarkCategory[category]
        if isinstance(category, str) and category in BenchmarkCategory.__members__
        else BenchmarkCategory.END_TO_END
    )
    return BenchmarkResult(
        name=result_name,
        category=category_value,
        elapsed_seconds=_float_field(data, "elapsed_seconds"),
        mean_seconds=_float_field(data, "mean_seconds"),
        stddev_seconds=_float_field(data, "stddev_seconds"),
        min_seconds=_float_field(data, "min_seconds"),
        max_seconds=_float_field(data, "max_seconds"),
    )
