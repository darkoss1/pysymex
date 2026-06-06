from __future__ import annotations

from pathlib import Path

from _pytest.capture import CaptureFixture
from pytest import MonkeyPatch

from pysymex.benchmarks.suite import runner as runner_mod
from pysymex.benchmarks.suite.core import Benchmark, BenchmarkSuite
from pysymex.benchmarks.suite.types import BenchmarkCategory, BenchmarkMode


def _small_suite() -> BenchmarkSuite:
    suite = BenchmarkSuite("test")
    suite.add(
        Benchmark(
            "quick_case",
            func=lambda: {"instructions": 1},
            category=BenchmarkCategory.SOLVING,
            modes=frozenset((BenchmarkMode.QUICK,)),
            aliases=("legacy_quick_case",),
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
    capsys: CaptureFixture[str],
) -> None:
    monkeypatch.setattr(runner_mod, "create_builtin_benchmarks", _small_suite)

    status = runner_mod.run_benchmarks(mode="all", list_cases=True)
    captured = capsys.readouterr()

    assert status == 0
    assert "quick_case" in captured.out
    assert "stress_case" in captured.out


def test_run_benchmarks_default_list_remains_quick_only(
    monkeypatch: MonkeyPatch,
    capsys: CaptureFixture[str],
) -> None:
    monkeypatch.setattr(runner_mod, "create_builtin_benchmarks", _small_suite)

    status = runner_mod.run_benchmarks(list_cases=True)
    captured = capsys.readouterr()

    assert status == 0
    assert "quick_case" in captured.out
    assert "stress_case" not in captured.out


def test_run_benchmarks_writes_requested_markdown_format(
    monkeypatch: MonkeyPatch,
    capsys: CaptureFixture[str],
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(runner_mod, "create_builtin_benchmarks", _small_suite)
    output_path = tmp_path / "bench.md"

    status = runner_mod.run_benchmarks(
        output_path=output_path,
        format="markdown",
        iterations=1,
        warmup=0,
        mode="quick",
    )
    captured = capsys.readouterr()

    assert status == 0
    assert "| quick_case |" in output_path.read_text(encoding="utf-8")
    assert output_path.read_text(encoding="utf-8").startswith("| Benchmark |")
    assert "| quick_case |" in captured.out


def test_run_benchmarks_normalizes_legacy_baseline_alias(
    monkeypatch: MonkeyPatch,
    capsys: CaptureFixture[str],
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(runner_mod, "create_builtin_benchmarks", _small_suite)
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(
        '[{"name":"legacy_quick_case","category":"SOLVING","mean_seconds":0.000000001}]',
        encoding="utf-8",
    )

    status = runner_mod.run_benchmarks(
        baseline_path=baseline_path,
        iterations=1,
        warmup=0,
        mode="quick",
        threshold_percent=0,
    )
    captured = capsys.readouterr()

    assert status == 1
    assert "**quick_case**" in captured.out
    assert "legacy_quick_case" not in captured.out
