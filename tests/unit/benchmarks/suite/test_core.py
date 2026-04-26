from __future__ import annotations

import json
from pathlib import Path

from pysymex.benchmarks.suite.core import (
    Benchmark,
    BenchmarkComparator,
    BenchmarkReporter,
    BenchmarkSuite,
    benchmark,
)
from pysymex.benchmarks.suite.types import BenchmarkCategory, BenchmarkResult


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


def test_reporter_and_comparator_outputs(tmp_path: Path) -> None:
    baseline = [
        BenchmarkResult("b1", BenchmarkCategory.OPCODES, elapsed_seconds=1.0, mean_seconds=1.0),
    ]
    current = [
        BenchmarkResult("b1", BenchmarkCategory.OPCODES, elapsed_seconds=1.3, mean_seconds=1.3),
    ]

    regressions = BenchmarkComparator(threshold_percent=10.0).compare(baseline, current)
    assert len(regressions) == 1
    assert regressions[0].is_regression is True

    as_json = BenchmarkReporter.to_json(current)
    as_md = BenchmarkReporter.to_markdown(current)
    out = tmp_path / "bench.json"
    BenchmarkReporter.to_json_file(current, out)

    assert json.loads(as_json)[0]["name"] == "b1"
    assert "| Benchmark |" in as_md
    assert out.exists()
