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

from pysymex._internal.benchmarks.suite.core import (
    Benchmark,
    BenchmarkSuite,
)
from pysymex._internal.benchmarks.suite.types import (
    BenchmarkCategory,
    BenchmarkMode,
    BenchmarkStatus,
)


def test_benchmark_run_collects_result_metrics() -> None:
    bench = Benchmark(
        name="toy",
        func=lambda: {
            "instructions": 42,
            "paths": 2,
            "solver_calls": 4,
            "solver_sat": 2,
            "solver_unsat": 1,
            "solver_unknown": 1,
            "issues": 3,
        },
        category=BenchmarkCategory.OPCODES,
    )
    result = bench.run(iterations=1, warmup=0)

    assert result.name == "toy"
    assert result.category is BenchmarkCategory.OPCODES
    assert result.instructions_executed == 42
    assert result.paths_explored == 2
    assert result.solver_calls == 4
    assert result.solver_sat == 2
    assert result.solver_unsat == 1
    assert result.solver_unknown == 1
    assert result.issue_count == 3


def test_suite_run_all_executes_setup_and_teardown() -> None:
    calls: list[str] = []

    def setup() -> None:
        calls.append("setup")

    def teardown() -> None:
        calls.append("teardown")

    suite = BenchmarkSuite("s", setup=setup, teardown=teardown)
    suite.add(Benchmark("b", func=lambda: {}, category=BenchmarkCategory.END_TO_END))
    results = suite.run_all(iterations=1, warmup=0)

    assert len(results) == 1
    assert calls == ["setup", "teardown"]


def test_suite_run_all_filters_by_mode_and_category() -> None:
    suite = BenchmarkSuite("s")
    suite.add(
        Benchmark(
            "quick_solver",
            func=lambda: {},
            category=BenchmarkCategory.SOLVING,
            modes=frozenset((BenchmarkMode.QUICK,)),
        )
    )
    suite.add(
        Benchmark(
            "stress_solver",
            func=lambda: {},
            category=BenchmarkCategory.SOLVING,
            modes=frozenset((BenchmarkMode.STRESS,)),
        )
    )

    results = suite.run_all(
        iterations=1,
        warmup=0,
        mode=BenchmarkMode.QUICK,
        category=BenchmarkCategory.SOLVING,
    )

    assert [result.name for result in results] == ["quick_solver"]


def test_suite_run_all_mode_none_runs_every_registered_case() -> None:
    suite = BenchmarkSuite("s")
    suite.add(
        Benchmark(
            "quick_solver",
            func=lambda: {},
            category=BenchmarkCategory.SOLVING,
            modes=frozenset((BenchmarkMode.QUICK,)),
        )
    )
    suite.add(
        Benchmark(
            "stress_solver",
            func=lambda: {},
            category=BenchmarkCategory.SOLVING,
            modes=frozenset((BenchmarkMode.STRESS,)),
        )
    )

    results = suite.run_all(iterations=1, warmup=0, mode=None)

    assert [result.name for result in results] == ["quick_solver", "stress_solver"]


def test_suite_select_uses_current_benchmark_name_only() -> None:
    suite = BenchmarkSuite("s")
    suite.add(
        Benchmark(
            "short_case",
            func=lambda: {},
            category=BenchmarkCategory.SOLVING,
        )
    )

    selected = suite.select(mode=None, case_name="long_case_name")

    assert selected == []
    assert [benchmark.name for benchmark in suite.select(mode=None, case_name="short_case")] == [
        "short_case"
    ]


def test_benchmark_run_reports_failure_status() -> None:
    def fail() -> None:
        raise RuntimeError("boom")

    result = Benchmark("failing", func=fail).run(iterations=1, warmup=0)

    assert result.status is BenchmarkStatus.FAILED
    assert result.failure is not None
    assert "boom" in result.failure
