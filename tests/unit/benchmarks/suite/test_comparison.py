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

from __future__ import annotations

from pysymex._internal.benchmarks.suite.comparison import BenchmarkComparator
from pysymex._internal.benchmarks.suite.types import BenchmarkCategory, BenchmarkResult


def test_comparator_detects_regressions() -> None:
    baseline = [
        BenchmarkResult("b1", BenchmarkCategory.OPCODES, elapsed_seconds=1.0, mean_seconds=1.0),
    ]
    current = [
        BenchmarkResult("b1", BenchmarkCategory.OPCODES, elapsed_seconds=1.3, mean_seconds=1.3),
    ]

    regressions = BenchmarkComparator(threshold_percent=10.0).compare(baseline, current)
    assert len(regressions) == 1
    assert regressions[0].is_regression is True
    assert "30.0% slower" in regressions[0].change_description
