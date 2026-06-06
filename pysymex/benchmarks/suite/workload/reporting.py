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

"""Reporting and formatter benchmark workloads."""

from __future__ import annotations

from datetime import datetime

from pysymex.analysis.scan.records import IssueRecord
from pysymex.cli.formatters import get_formatter
from pysymex.scanner.types import ScanResult

_FORMAT_NAMES = ("json", "markdown", "html", "sarif")
_reporting_results_cache: tuple[ScanResult, ...] | None = None


def _issue(kind: str, line: int, variable: str) -> IssueRecord:
    """Build a deterministic synthetic scanner issue record."""
    return {
        "kind": kind,
        "message": f"{kind.lower()} benchmark issue",
        "line": line,
        "function_name": f"target_{line}",
        "counterexample": {variable: 0},
    }


def _reporting_results() -> tuple[ScanResult, ...]:
    """Return reusable scan results for formatter throughput measurement."""
    global _reporting_results_cache
    if _reporting_results_cache is None:
        timestamp = datetime(2026, 1, 1).isoformat()
        issue_kinds = (
            "DIVISION_BY_ZERO",
            "ASSERTION_ERROR",
            "INDEX_ERROR",
            "KEY_ERROR",
        )
        results: list[ScanResult] = []
        for file_index, kind in enumerate(issue_kinds, start=1):
            issues = tuple(
                _issue(kind, file_index * 10 + offset, f"x_{file_index}_{offset}")
                for offset in range(3)
            )
            results.append(
                ScanResult(
                    file_path=f"benchmark_target_{file_index}.py",
                    timestamp=timestamp,
                    issues=list(issues),
                    code_objects=3,
                    paths_explored=12,
                    elapsed_time=0.05,
                    avg_memory_mb=18.0,
                    solver_stats={
                        "queries": 8,
                        "sat_results": 5,
                        "unsat_results": 3,
                        "unknown_results": 0,
                    },
                )
            )
        _reporting_results_cache = tuple(results)
    return _reporting_results_cache


def _solver_query_count(result: ScanResult) -> int:
    """Return the non-negative solver query count recorded on a scan result."""
    value = result.solver_stats.get("queries", 0)
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return max(0, value)


def bench_reporting_formatters() -> dict[str, int]:
    """Benchmark JSON, Markdown, HTML, and SARIF scan report formatting."""
    results = _reporting_results()
    issue_count = sum(len(result.issues) for result in results)
    output_bytes = 0
    for format_name in _FORMAT_NAMES:
        output = get_formatter(format_name).format_symbolic(
            results,
            issue_count,
            duration=0.25,
            reproduce=False,
            show_stats=True,
        )
        output_bytes += len(output.encode("utf-8"))

    return {
        "instructions": output_bytes,
        "paths": sum(result.paths_explored for result in results),
        "solver_calls": sum(_solver_query_count(result) for result in results),
        "issues": issue_count,
    }
