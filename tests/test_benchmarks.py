"""Tests for benchmarking suite."""

import importlib.util

import json

import sys

import types

from pathlib import Path

from types import SimpleNamespace

from unittest.mock import Mock, patch


import pytest


from pysymex.benchmarks import (
    BenchmarkCategory,
    BenchmarkResult,
    BenchmarkSuite,
    Benchmark,
    benchmark,
    BenchmarkReporter,
    RegressionResult,
    BenchmarkComparator,
    create_builtin_benchmarks,
)


class TestBenchmarkResult:
    """Tests for BenchmarkResult."""

    def test_create_result(self):
        """Test creating a benchmark result."""

        result = BenchmarkResult(
            name="test_bench",
            category=BenchmarkCategory.OPCODES,
            elapsed_seconds=1.5,
            mean_seconds=0.3,
        )

        assert result.name == "test_bench"

        assert result.category == BenchmarkCategory.OPCODES

        assert result.elapsed_seconds == 1.5

    def test_throughput(self):
        """Test throughput calculation."""

        result = BenchmarkResult(
            name="test",
            category=BenchmarkCategory.OPCODES,
            elapsed_seconds=2.0,
            instructions_executed=1000,
        )

        assert result.throughput == 500.0

    def test_throughput_zero_time(self):
        """Test throughput with zero time."""

        result = BenchmarkResult(
            name="test",
            category=BenchmarkCategory.OPCODES,
            elapsed_seconds=0,
            instructions_executed=100,
        )

        assert result.throughput == 0.0

    def test_paths_per_second(self):
        """Test paths per second calculation."""

        result = BenchmarkResult(
            name="test",
            category=BenchmarkCategory.PATHS,
            elapsed_seconds=5.0,
            paths_explored=25,
        )

        assert result.paths_per_second == 5.0

    def test_to_dict(self):
        """Test conversion to dictionary."""

        result = BenchmarkResult(
            name="test",
            category=BenchmarkCategory.MEMORY,
            elapsed_seconds=1.0,
            mean_seconds=1.0,
            peak_memory_mb=50.0,
        )

        d = result.to_dict()

        assert d["name"] == "test"

        assert d["category"] == "MEMORY"

        assert d["peak_memory_mb"] == 50.0


class TestBenchmark:
    """Tests for Benchmark class."""

    def test_create_benchmark(self):
        """Test creating a benchmark."""

        def sample_func():
            return {"instructions": 10}

        bench = Benchmark(
            name="sample",
            func=sample_func,
            category=BenchmarkCategory.OPCODES,
        )

        assert bench.name == "sample"

        assert bench.category == BenchmarkCategory.OPCODES

    def test_run_benchmark(self):
        """Test running a benchmark."""

        call_count = [0]

        def sample_func():
            call_count[0] += 1

            return {"instructions": 100}

        bench = Benchmark(name="test", func=sample_func)

        result = bench.run(iterations=3, warmup=1)

        assert call_count[0] == 4

        assert result.iterations == 3

    def test_benchmark_timing(self):
        """Test benchmark captures timing."""

        import time

        def slow_func():
            time.sleep(0.01)

            return {}

        bench = Benchmark(name="slow", func=slow_func)

        result = bench.run(iterations=2, warmup=0)

        assert result.mean_seconds >= 0.01

        assert result.min_seconds > 0


class TestBenchmarkDecorator:
    """Tests for @benchmark decorator."""

    def test_decorator_creates_benchmark(self):
        """Test decorator creates benchmark attribute."""

        @benchmark(name="decorated", category=BenchmarkCategory.ANALYSIS)
        def my_benchmark():
            return {}

        assert hasattr(my_benchmark, "_benchmark")

        assert my_benchmark._benchmark.name == "decorated"

    def test_decorator_uses_function_name(self):
        """Test decorator uses function name if not specified."""

        @benchmark()
        def auto_named():
            return {}

        assert auto_named._benchmark.name == "auto_named"


class TestBenchmarkSuite:
    """Tests for BenchmarkSuite."""

    def test_create_suite(self):
        """Test creating a benchmark suite."""

        suite = BenchmarkSuite(
            name="test_suite",
            description="Test suite",
        )

        assert suite.name == "test_suite"

        assert len(suite.benchmarks) == 0

    def test_add_benchmark(self):
        """Test adding benchmarks to suite."""

        suite = BenchmarkSuite(name="suite")

        bench = Benchmark(name="b1", func=lambda: {})

        suite.add(bench)

        assert bench in suite.benchmarks

    def test_run_all(self):
        """Test running all benchmarks in suite."""

        suite = BenchmarkSuite(name="suite")

        suite.add(Benchmark(name="b1", func=lambda: {}))

        suite.add(Benchmark(name="b2", func=lambda: {}))

        results = suite.run_all(iterations=1, warmup=0)

        assert len(results) == 2

    def test_setup_teardown(self):
        """Test suite setup and teardown."""

        setup_called = [False]

        teardown_called = [False]

        def setup():
            setup_called[0] = True

        def teardown():
            teardown_called[0] = True

        suite = BenchmarkSuite(
            name="suite",
            setup=setup,
            teardown=teardown,
        )

        suite.add(Benchmark(name="b", func=lambda: {}))

        suite.run_all(iterations=1, warmup=0)

        assert setup_called[0]

        assert teardown_called[0]


class TestBenchmarkReporter:
    """Tests for BenchmarkReporter."""

    def test_to_json(self):
        """Test JSON output."""

        results = [
            BenchmarkResult(
                name="test1",
                category=BenchmarkCategory.OPCODES,
                elapsed_seconds=1.0,
            ),
        ]

        json_str = BenchmarkReporter.to_json(results)

        data = json.loads(json_str)

        assert len(data) == 1

        assert data[0]["name"] == "test1"

    def test_to_markdown(self):
        """Test Markdown output."""

        results = [
            BenchmarkResult(
                name="test",
                category=BenchmarkCategory.MEMORY,
                elapsed_seconds=1.0,
                mean_seconds=1.0,
                stddev_seconds=0.1,
                peak_memory_mb=25.0,
            ),
        ]

        md = BenchmarkReporter.to_markdown(results)

        assert "| test |" in md

        assert "MEMORY" in md

    def test_to_console(self, capsys):
        """Test console output."""

        results = [
            BenchmarkResult(
                name="console_test",
                category=BenchmarkCategory.END_TO_END,
                elapsed_seconds=0.5,
                mean_seconds=0.5,
            ),
        ]

        BenchmarkReporter.to_console(results)

        captured = capsys.readouterr()

        assert "console_test" in captured.out


class TestRegressionResult:
    """Tests for RegressionResult."""

    def test_create_regression_result(self):
        """Test creating regression result."""

        result = RegressionResult(
            benchmark_name="test",
            baseline_mean=1.0,
            current_mean=1.5,
            change_percent=50.0,
            is_regression=True,
            threshold_percent=10.0,
        )

        assert result.is_regression

        assert result.change_percent == 50.0

    def test_change_description_slower(self):
        """Test change description for slower."""

        result = RegressionResult(
            benchmark_name="test",
            baseline_mean=1.0,
            current_mean=1.2,
            change_percent=20.0,
            is_regression=True,
            threshold_percent=10.0,
        )

        assert "slower" in result.change_description

    def test_change_description_faster(self):
        """Test change description for faster."""

        result = RegressionResult(
            benchmark_name="test",
            baseline_mean=1.0,
            current_mean=0.8,
            change_percent=-20.0,
            is_regression=False,
            threshold_percent=10.0,
        )

        assert "faster" in result.change_description


class TestBenchmarkComparator:
    """Tests for BenchmarkComparator."""

    def test_compare_no_regression(self):
        """Test comparison with no regression."""

        comparator = BenchmarkComparator(threshold_percent=10.0)

        baseline = [
            BenchmarkResult(
                name="b1", category=BenchmarkCategory.OPCODES, elapsed_seconds=1.0, mean_seconds=1.0
            ),
        ]

        current = [
            BenchmarkResult(
                name="b1",
                category=BenchmarkCategory.OPCODES,
                elapsed_seconds=1.05,
                mean_seconds=1.05,
            ),
        ]

        regressions = comparator.compare(baseline, current)

        assert len(regressions) == 1

        assert not regressions[0].is_regression

    def test_compare_with_regression(self):
        """Test comparison detecting regression."""

        comparator = BenchmarkComparator(threshold_percent=10.0)

        baseline = [
            BenchmarkResult(
                name="b1", category=BenchmarkCategory.OPCODES, elapsed_seconds=1.0, mean_seconds=1.0
            ),
        ]

        current = [
            BenchmarkResult(
                name="b1", category=BenchmarkCategory.OPCODES, elapsed_seconds=1.5, mean_seconds=1.5
            ),
        ]

        regressions = comparator.compare(baseline, current)

        assert regressions[0].is_regression

        assert regressions[0].change_percent == 50.0

    def test_report_regressions(self):
        """Test regression report generation."""

        comparator = BenchmarkComparator()

        regressions = [
            RegressionResult(
                benchmark_name="failing",
                baseline_mean=1.0,
                current_mean=1.5,
                change_percent=50.0,
                is_regression=True,
                threshold_percent=10.0,
            ),
        ]

        report = comparator.report_regressions(regressions)

        assert "Regression" in report

        assert "failing" in report


class TestBuiltinBenchmarks:
    """Tests for built-in benchmarks."""

    def test_create_builtin_suite(self):
        """Test creating built-in benchmark suite."""

        suite = create_builtin_benchmarks()

        assert suite is not None

        assert len(suite.benchmarks) >= 1

    def test_run_builtin_benchmarks(self):
        """Test running built-in benchmarks."""

        suite = create_builtin_benchmarks()

        results = suite.run_all(iterations=1, warmup=0)

        assert len(results) >= 1

        for result in results:
            assert result.elapsed_seconds >= 0


class TestBenchmarkCLI:
    """Tests for the CLI benchmark command wiring."""

    @staticmethod
    def _load_cli_module():
        module_name = "pysymex_cli_bench_test"

        if module_name in sys.modules:
            del sys.modules[module_name]

        cli_path = Path(__file__).resolve().parents[1] / "pysymex" / "cli" / "__init__.py"

        spec = importlib.util.spec_from_file_location(module_name, cli_path)

        assert spec and spec.loader

        module = importlib.util.module_from_spec(spec)

        spec.loader.exec_module(module)

        return module

    def test_main_dispatches_benchmark(self, monkeypatch):
        cli = self._load_cli_module()

        captured = {}

        def fake_cmd_benchmark(args):
            captured["format"] = args.format

            return 7

        monkeypatch.setattr(cli, "cmd_benchmark", fake_cmd_benchmark)

        assert cli.main(["benchmark", "--format", "markdown"]) == 7

        assert captured["format"] == "markdown"

    def test_cmd_benchmark_forwards_arguments(self, monkeypatch):
        cli = self._load_cli_module()

        captured = {}

        fake_benchmarks = types.ModuleType("pysymex.benchmarks")

        def fake_run_benchmarks(*, output_path, baseline_path, format, iterations):
            captured["output_path"] = output_path

            captured["baseline_path"] = baseline_path

            captured["format"] = format

            captured["iterations"] = iterations

            return 0

        fake_benchmarks.run_benchmarks = fake_run_benchmarks

        monkeypatch.setitem(sys.modules, "pysymex.benchmarks", fake_benchmarks)

        args = SimpleNamespace(
            output="bench.json",
            baseline="baseline.json",
            format="json",
            iterations=3,
        )

        assert cli.cmd_benchmark(args) == 0

        assert captured["output_path"] == Path("bench.json")

        assert captured["baseline_path"] == Path("baseline.json")

        assert captured["format"] == "json"

        assert captured["iterations"] == 3
