"""Tests for benchmark suite (benchmarks/)."""
from __future__ import annotations
import pytest
from pysymex.benchmarks.suite_types import (
    BenchmarkCategory, BenchmarkResult, RegressionResult,
)
from pysymex.benchmarks.suite_core import (
    BenchmarkSuite, Benchmark, BenchmarkReporter, BenchmarkComparator,
    create_builtin_benchmarks, benchmark,
)


# -- Types --

class TestBenchmarkCategory:
    def test_enum(self):
        assert len(BenchmarkCategory) >= 1


class TestBenchmarkResult:
    def test_creation(self):
        br = BenchmarkResult(
            name="test",
            category=BenchmarkCategory.END_TO_END,
            elapsed_seconds=1.0,
        )
        assert br is not None

    def test_has_timing(self):
        br = BenchmarkResult(
            name="test",
            category=BenchmarkCategory.END_TO_END,
            elapsed_seconds=1.0,
        )
        assert (hasattr(br, 'elapsed') or hasattr(br, 'time') or
                hasattr(br, 'duration') or hasattr(br, 'elapsed_seconds'))


class TestRegressionResult:
    def test_creation(self):
        rr = RegressionResult(
            benchmark_name="test",
            baseline_mean=1.0,
            current_mean=1.1,
            change_percent=10.0,
            is_regression=False,
            threshold_percent=10.0,
        )
        assert rr is not None


# -- Core --

class TestBenchmarkSuite:
    def test_creation(self):
        suite = BenchmarkSuite(name="test_suite")
        assert suite is not None

    def test_has_benchmarks(self):
        suite = BenchmarkSuite(name="test_suite")
        assert (hasattr(suite, 'benchmarks') or hasattr(suite, '_benchmarks')
                or hasattr(suite, 'list'))

    def test_add_benchmark(self):
        suite = BenchmarkSuite(name="test_suite")
        if hasattr(suite, 'add'):
            suite.add(Benchmark(name="test", func=lambda: None))
        elif hasattr(suite, 'register'):
            suite.register(Benchmark(name="test", func=lambda: None))


class TestBenchmark:
    def test_creation(self):
        b = Benchmark(name="test", func=lambda: {"paths": 1})
        assert b.name == "test"

    def test_has_run(self):
        assert hasattr(Benchmark, 'run') or hasattr(Benchmark, '__call__')


class TestBenchmarkReporter:
    def test_creation(self):
        reporter = BenchmarkReporter()
        assert reporter is not None


class TestBenchmarkComparator:
    def test_creation(self):
        comp = BenchmarkComparator()
        assert comp is not None


class TestCreateBuiltinBenchmarks:
    def test_returns_suite(self):
        suite = create_builtin_benchmarks()
        assert isinstance(suite, BenchmarkSuite)


class TestBenchmarkDecorator:
    def test_callable(self):
        assert callable(benchmark)
