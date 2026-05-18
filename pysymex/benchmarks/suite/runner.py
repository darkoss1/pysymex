# pysymex: Python Symbolic Execution & Formal Verification
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

"""Benchmark execution runner for pysymex."""

from __future__ import annotations

import json
from pathlib import Path

from pysymex.benchmarks.suite.comparison import BenchmarkComparator
from pysymex.benchmarks.suite.reporting import BenchmarkReporter
from pysymex.benchmarks.suite.types import BenchmarkCategory, BenchmarkResult
from pysymex.benchmarks.suite.workloads import create_builtin_benchmarks


def run_benchmarks(
    output_path: Path | None = None,
    baseline_path: Path | None = None,
    format: str = "console",
    iterations: int = 5,
    case_name: str | None = None,
) -> int:
    """Run the built-in benchmarks from the CLI.

    Args:
        output_path: Optional file path for JSON output.
        baseline_path: Optional baseline JSON for regression comparison.
        format: Output format (``console``, ``json``, ``markdown``).
        iterations: Number of timing iterations per benchmark.

    Returns:
        ``0`` on success, ``1`` if regressions are detected.
    """
    suite = create_builtin_benchmarks()
    results = suite.run_all(iterations=iterations, case_name=case_name)
    if format == "json" and output_path:
        BenchmarkReporter.to_json_file(results, output_path)
    elif format == "markdown":
        print(BenchmarkReporter.to_markdown(results))
    else:
        BenchmarkReporter.to_console(results)
    if baseline_path and baseline_path.exists():
        baseline_data = json.loads(baseline_path.read_text())
        baseline = [
            BenchmarkResult(
                name=d["name"],
                category=BenchmarkCategory[d["category"]],
                elapsed_seconds=d["elapsed_seconds"],
                mean_seconds=d["mean_seconds"],
                stddev_seconds=d.get("stddev_seconds", 0),
                min_seconds=d.get("min_seconds", 0),
                max_seconds=d.get("max_seconds", 0),
            )
            for d in baseline_data
        ]
        comparator = BenchmarkComparator()
        regressions = comparator.compare(baseline, results)
        print(comparator.report_regressions(regressions))
        if any(r.is_regression for r in regressions):
            return 1
    return 0
