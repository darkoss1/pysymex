from __future__ import annotations

import sys
from unittest.mock import patch

import z3

from pysymex.accel.backends import reference
from pysymex.accel.benchmark import (
    BenchmarkConfig,
    BenchmarkResult,
    SystemInfo,
    Z3ModuleLike,
    create_random_3sat,
    get_system_info,
    main,
    run_benchmarks,
    run_single_benchmark,
)


class _Z3Adapter:
    def Bool(self, name: str) -> z3.BoolRef:
        return z3.Bool(name)

    def Not(self, *args: object, **kwargs: object) -> z3.BoolRef:
        assert len(args) >= 1
        expr = args[0]
        assert isinstance(expr, (z3.BoolRef, z3.ExprRef, bool))
        assert kwargs == {}
        return z3.Not(expr)

    def Or(self, *args: object, **kwargs: object) -> z3.BoolRef:
        validated: list[z3.BoolRef | z3.ExprRef | bool] = []
        for arg in args:
            assert isinstance(arg, (z3.BoolRef, z3.ExprRef, bool))
            validated.append(arg)
        assert kwargs == {}
        return z3.Or(*validated)

    def And(self, *args: object, **kwargs: object) -> z3.BoolRef:
        validated: list[z3.BoolRef | z3.ExprRef | bool] = []
        for arg in args:
            assert isinstance(arg, (z3.BoolRef, z3.ExprRef, bool))
            validated.append(arg)
        assert kwargs == {}
        return z3.And(*validated)


def test_benchmark_config_initialization() -> None:
    config = BenchmarkConfig(
        treewidths=[2, 3],
        iterations=5,
        warmup_iterations=1,
        clause_ratio=4.0,
        random_seed=7,
    )

    assert config.treewidths == [2, 3]
    assert config.iterations == 5
    assert config.warmup_iterations == 1
    assert config.clause_ratio == 4.0
    assert config.random_seed == 7


def test_benchmark_result_initialization() -> None:
    result = BenchmarkResult(
        backend="Reference",
        treewidth=2,
        num_states=4,
        num_instructions=3,
        num_satisfying=2,
        compile_time_ms=1.0,
        kernel_time_ms=2.0,
        kernel_time_std_ms=0.1,
        total_time_ms=3.0,
        throughput_mops=0.5,
    )

    assert result.backend == "Reference"
    assert result.treewidth == 2
    assert result.num_states == 4
    assert result.num_satisfying == 2


def test_system_info_initialization() -> None:
    info = SystemInfo(
        python_version="3.13.0",
        platform="win32",
        processor="x86_64",
        numba_version=None,
        cuda_device=None,
        backends_available=["Reference"],
    )

    assert info.python_version == "3.13.0"
    assert info.backends_available == ["Reference"]


def test_get_system_info_has_expected_shape() -> None:
    info = get_system_info()
    assert isinstance(info.python_version, str)
    assert len(info.python_version) > 0
    assert isinstance(info.platform, str)
    assert isinstance(info.backends_available, list)


def test_create_random_3sat_is_deterministic_for_seed() -> None:
    z3_module: Z3ModuleLike = _Z3Adapter()
    expr_a, names_a = create_random_3sat(z3_module, num_vars=4, clause_ratio=2.0, seed=123)
    expr_b, names_b = create_random_3sat(z3_module, num_vars=4, clause_ratio=2.0, seed=123)

    assert names_a == ["x0", "x1", "x2", "x3"]
    assert names_a == names_b
    assert z3.eq(expr_a, expr_b)


def test_run_single_benchmark_reference_success() -> None:
    config = BenchmarkConfig(
        treewidths=[3],
        iterations=1,
        warmup_iterations=0,
        clause_ratio=2.0,
        random_seed=1,
    )

    result = run_single_benchmark(
        reference,
        "Reference",
        treewidth=3,
        config=config,
        z3_module=_Z3Adapter(),
    )

    assert result is not None
    assert result.backend == "Reference"
    assert result.treewidth == 3
    assert result.num_states == 8
    assert result.num_instructions >= 1
    assert result.num_satisfying >= 0
    assert result.kernel_time_ms >= 0.0


def test_run_single_benchmark_skips_when_treewidth_too_large() -> None:
    config = BenchmarkConfig(
        treewidths=[99],
        iterations=1,
        warmup_iterations=0,
        clause_ratio=2.0,
        random_seed=1,
    )

    result = run_single_benchmark(
        reference,
        "Reference",
        treewidth=10_000,
        config=config,
        z3_module=_Z3Adapter(),
    )
    assert result is None


def test_run_benchmarks_returns_serializable_payload() -> None:
    config = BenchmarkConfig(
        treewidths=[2],
        iterations=1,
        warmup_iterations=0,
        clause_ratio=2.0,
        random_seed=11,
    )

    payload = run_benchmarks(config)

    assert "system_info" in payload
    assert "config" in payload
    assert "results" in payload
    results_obj = payload["results"]
    assert isinstance(results_obj, list)
    assert results_obj != []


def test_main_parses_args_and_writes_output() -> None:
    fake_results: dict[str, object] = {"system_info": {}, "config": {}, "results": []}
    captured: list[BenchmarkConfig] = []

    argv = [
        "benchmark.py",
        "--treewidth",
        "2",
        "--iterations",
        "1",
        "--warmup",
        "0",
        "--seed",
        "9",
        "--output",
        "out.json",
    ]

    def _fake_run(config: BenchmarkConfig) -> dict[str, object]:
        captured.append(config)
        return fake_results

    with patch.object(sys, "argv", argv):
        with patch("pysymex.accel.benchmark.run_benchmarks", side_effect=_fake_run) as mocked_run:
            with patch("json.dump") as mocked_dump:
                with patch("builtins.open") as mocked_open:
                    main()

    assert mocked_run.call_count == 1
    assert len(captured) == 1
    config_arg = captured[0]
    assert config_arg.treewidths == [2]
    assert config_arg.iterations == 1
    assert config_arg.warmup_iterations == 0
    assert config_arg.random_seed == 9
    assert mocked_open.call_count == 1
    assert mocked_dump.call_count == 1
