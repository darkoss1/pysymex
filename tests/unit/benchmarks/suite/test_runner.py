from __future__ import annotations

from pathlib import Path

from pytest import MonkeyPatch

import pysymex._internal.benchmarks.suite.runner as runner_mod
from pysymex._internal.benchmarks.suite.core import Benchmark, BenchmarkSuite
from pysymex._internal.benchmarks.suite.types import BenchmarkCategory, BenchmarkMode


def _small_suite() -> BenchmarkSuite:
    suite = BenchmarkSuite("test")
    suite.add(
        Benchmark(
            "quick_case",
            func=lambda: {"instructions": 1},
            category=BenchmarkCategory.SOLVING,
            modes=frozenset((BenchmarkMode.QUICK,)),
        )
    )
    suite.add(
        Benchmark(
            "stress_case",
            func=lambda: {"instructions": 1},
            category=BenchmarkCategory.SOLVING,
            modes=frozenset((BenchmarkMode.STRESS,)),
        )
    )
    return suite


def test_run_benchmarks_all_mode_lists_every_case(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr(runner_mod, "create_builtin_benchmarks", _small_suite)

    result = runner_mod.run_benchmarks(mode="all", list_cases=True)

    assert result.exit_code == 0
    assert result.inventory == ["quick_case", "stress_case"]


def test_run_benchmarks_default_list_remains_quick_only(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr(runner_mod, "create_builtin_benchmarks", _small_suite)

    result = runner_mod.run_benchmarks(list_cases=True)

    assert result.exit_code == 0
    assert result.inventory == ["quick_case"]


def test_run_benchmarks_returns_selected_results(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr(runner_mod, "create_builtin_benchmarks", _small_suite)

    result = runner_mod.run_benchmarks(
        iterations=1,
        warmup=0,
        mode="quick",
    )

    assert result.exit_code == 0
    assert [item.name for item in result.results] == ["quick_case"]
    assert result.inventory == ["quick_case"]


def test_run_benchmarks_compares_baseline_current_names_only(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(runner_mod, "create_builtin_benchmarks", _small_suite)
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(
        '[{"name":"quick_case","category":"SOLVING","mean_seconds":0.000000001}]',
        encoding="utf-8",
    )

    result = runner_mod.run_benchmarks(
        baseline_path=baseline_path,
        iterations=1,
        warmup=0,
        mode="quick",
        threshold_percent=0,
    )

    assert result.exit_code == 1
    assert [regression.benchmark_name for regression in result.regressions] == ["quick_case"]
