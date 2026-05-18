# pysymex: Python Symbolic Execution & Formal Verification
from __future__ import annotations

from pysymex.benchmarks.suite.core import (
    Benchmark,
    BenchmarkSuite,
    benchmark,
)
from pysymex.benchmarks.suite.types import BenchmarkCategory


def test_benchmark_run_collects_result_metrics() -> None:
    bench = Benchmark(
        name="toy",
        func=lambda: {"instructions": 42, "paths": 2, "solver_calls": 1},
        category=BenchmarkCategory.OPCODES,
    )
    result = bench.run(iterations=1, warmup=0)

    assert result.name == "toy"
    assert result.category is BenchmarkCategory.OPCODES
    assert result.instructions_executed == 42
    assert result.paths_explored == 2


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


def test_benchmark_decorator_registers_benchmark_metadata() -> None:
    @benchmark(name="decorated", category=BenchmarkCategory.ANALYSIS)
    def task() -> dict[str, int]:
        return {"instructions": 1, "paths": 1, "solver_calls": 1}

    bench_obj = getattr(task, "_benchmark")
    assert isinstance(bench_obj, Benchmark)
    assert bench_obj.name == "decorated"
