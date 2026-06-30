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

"""Benchmark results comparison for pysymex."""

from __future__ import annotations

from pysymex._internal.benchmarks.suite.types import BenchmarkResult, RegressionResult


class BenchmarkComparator:
    """Compare current benchmark results against a baseline for regressions.

    Attributes:
        threshold_percent: Percentage increase that is flagged as a
            regression.

    """

    def __init__(self, threshold_percent: float = 10.0) -> None:
        """Args:
        threshold_percent: Percent change that triggers regression.

        """
        self.threshold_percent = threshold_percent

    def compare(
        self,
        baseline: list[BenchmarkResult],
        current: list[BenchmarkResult],
    ) -> list[RegressionResult]:
        """Compare baseline to current results."""
        baseline_by_name = {r.name: r for r in baseline}
        results: list[RegressionResult] = []
        for curr in current:
            if curr.name not in baseline_by_name:
                continue
            base = baseline_by_name[curr.name]
            if base.mean_seconds > 0:
                change = ((curr.mean_seconds - base.mean_seconds) / base.mean_seconds) * 100
            else:
                change = 0.0
            is_regression = change > self.threshold_percent
            results.append(
                RegressionResult(
                    benchmark_name=curr.name,
                    baseline_mean=base.mean_seconds,
                    current_mean=curr.mean_seconds,
                    change_percent=change,
                    is_regression=is_regression,
                    threshold_percent=self.threshold_percent,
                ),
            )
        return results

    def report_regressions(self, regressions: list[RegressionResult]) -> str:
        """Generate regression report."""
        lines = ["# Benchmark Comparison Report\n"]
        failures = [r for r in regressions if r.is_regression]
        if failures:
            lines.append(f"## [WARN] {len(failures)} Regression(s) Detected\n")
            for r in failures:
                lines.append(f"- **{r.benchmark_name}**: {r.change_description}")
                lines.append(f"  - Baseline: {r.baseline_mean * 1000:.2f} ms")
                lines.append(f"  - Current: {r.current_mean * 1000:.2f} ms\n")
        else:
            lines.append("## [OK] No Regressions Detected\n")
        lines.append("## All Results\n")
        for r in regressions:
            status = "[REGRESSION]" if r.is_regression else "[OK]"
            lines.append(f"{status} {r.benchmark_name}: {r.change_description}")
        return "\n".join(lines)
