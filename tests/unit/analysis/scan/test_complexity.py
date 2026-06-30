from pysymex._internal.analysis.scan.complexity import (
    ComplexityMetrics,
    analyze_complexity,
    recommended_timeout_ms,
    tune_execution_config,
)
from pysymex._internal.config.execution.settings import ExecutionConfig


class TestComplexityMetrics:
    """Test suite for pysymex._internal.analysis.scan.complexity."""

    def test_metrics_score(self) -> None:
        """Test ComplexityMetrics scoring logic."""
        metrics = ComplexityMetrics(
            instruction_count=10, branch_count=2, loop_count=1, call_count=1, score=14
        )
        assert metrics.score == 14

    def test_analyze_complexity(self) -> None:
        """Test analyze_complexity behavior."""

        def dummy_func(x: int) -> int:
            for i in range(x):
                if i > 5:
                    return i
            return 0

        code = dummy_func.__code__
        metrics = analyze_complexity(code)
        assert metrics.instruction_count > 0
        assert metrics.branch_count >= 1  # if i > 5
        assert metrics.loop_count >= 1  # for i in range(x)
        assert metrics.call_count >= 1  # range(x)
        assert metrics.score == (
            metrics.branch_count * 3
            + metrics.loop_count * 5
            + metrics.call_count * 2
            + metrics.instruction_count // 10
        )

    def test_analyze_complexity_counts_keyword_calls(self) -> None:
        """CALL_KW contributes to call complexity on Python 3.13+."""

        def callee(*, value: int) -> int:
            return value

        def caller() -> int:
            return callee(value=1)

        metrics = analyze_complexity(caller.__code__)

        assert metrics.call_count >= 1

    def test_recommended_timeout_ms(self) -> None:
        """Test complexity-score timeout recommendations."""

        def dummy_func() -> None:
            pass

        code = dummy_func.__code__
        metrics = analyze_complexity(code)
        assert recommended_timeout_ms(metrics.score) >= 2000
        assert metrics.instruction_count > 0

    def test_tune_execution_config_preserves_automatic_limits(self) -> None:
        """Complexity tuning must not create implicit host stop conditions."""

        def dummy_func() -> None:
            pass

        code = dummy_func.__code__
        base_config = ExecutionConfig()
        config = tune_execution_config(code, base_config)
        assert isinstance(config, ExecutionConfig)
        assert config.max_paths is None
        assert config.max_depth is None
        assert config.max_iterations is None
        assert config.timeout_seconds is None

    def test_tune_execution_config_can_tighten_explicit_limits(self) -> None:
        """Complexity tuning may adjust limits explicitly supplied by a caller."""

        def dummy_func() -> None:
            pass

        config = tune_execution_config(
            dummy_func.__code__,
            ExecutionConfig(
                max_paths=1000,
                max_depth=1000,
                max_iterations=10_000,
                timeout_seconds=60.0,
            ),
        )

        assert config.max_paths == 100
        assert config.max_iterations == 2000
        assert config.timeout_seconds == 10.0

    def test_tune_execution_config_tunes_solver_timeout(self) -> None:
        """Complexity tuning automatically sets a recommended solver_timeout_ms."""
        def dummy_func() -> None:
            pass

        # For simple score, default solver timeout is tuned down from 10000 to recommended (e.g. 2000)
        config = tune_execution_config(dummy_func.__code__, ExecutionConfig())
        assert config.solver_timeout_ms < 10000
        assert config.solver_timeout_ms >= 2000

        # If user explicitly overrode solver_timeout_ms (e.g., 500), it should be respected
        config_override = tune_execution_config(
            dummy_func.__code__,
            ExecutionConfig(solver_timeout_ms=500),
        )
        assert config_override.solver_timeout_ms == 500

    def test_tune_execution_config_respects_max_loop_iterations_override(self) -> None:
        """Complexity tuning respects explicit max_loop_iterations overrides."""
        def dummy_func_with_loop(x: int) -> int:
            for _i in range(x):
                pass
            return 0

        # No explicit override -> sets candidate loop iteration limit (30)
        config_no_override = tune_execution_config(
            dummy_func_with_loop.__code__,
            ExecutionConfig(max_loop_iterations=None),
        )
        assert config_no_override.max_loop_iterations == 30

        # Explicit override (e.g. 3) -> respects it (should be min(3, 10) = 3)
        config_with_override = tune_execution_config(
            dummy_func_with_loop.__code__,
            ExecutionConfig(max_loop_iterations=3),
        )
        assert config_with_override.max_loop_iterations == 3

    def test_tune_execution_config_multi_tiered_scaling(self) -> None:
        """Complexity tuning correctly scales through multi-tiered limits and merge policies."""
        from unittest.mock import patch
        from pysymex._internal.analysis.scan.complexity import ComplexityMetrics

        def dummy_func() -> None:
            pass

        # 1. Medium-Low Tier (Score = 30)
        with patch("pysymex._internal.analysis.scan.complexity.analyze_complexity") as mock_analyze:
            mock_analyze.return_value = ComplexityMetrics(
                instruction_count=100, branch_count=5, loop_count=1, call_count=3, score=30
            )
            # Tightened moderately if user limits are higher
            config_tight = tune_execution_config(
                dummy_func.__code__,
                ExecutionConfig(max_paths=1000, timeout_seconds=60.0, max_iterations=10000),
            )
            assert config_tight.max_paths == 500
            assert config_tight.timeout_seconds == 20.0
            assert config_tight.max_iterations == 5000

            # Default fallback when user limits are None (stay None to avoid implicit host stops)
            config_default = tune_execution_config(
                dummy_func.__code__,
                ExecutionConfig(),
            )
            assert config_default.max_paths is None
            assert config_default.timeout_seconds is None
            assert config_default.max_iterations is None

        # 2. Very High Tier (Score = 250)
        with patch("pysymex._internal.analysis.scan.complexity.analyze_complexity") as mock_analyze:
            mock_analyze.return_value = ComplexityMetrics(
                instruction_count=500, branch_count=40, loop_count=5, call_count=20, score=250
            )
            # Default fallback when user limits are None (stay None to avoid implicit host stops)
            config_default = tune_execution_config(
                dummy_func.__code__,
                ExecutionConfig(),
            )
            assert config_default.max_paths is None
            assert config_default.timeout_seconds is None
            assert config_default.max_iterations is None
            assert config_default.merge_policy == "aggressive"
            assert config_default.lazy_eval_threshold == 50

            # Never exceed user-specified limits (capped by min clamp)
            config_capped = tune_execution_config(
                dummy_func.__code__,
                ExecutionConfig(max_paths=180, timeout_seconds=60.0, max_iterations=4500),
            )
            assert config_capped.max_paths == 180
            assert config_capped.timeout_seconds == 60.0
            assert config_capped.max_iterations == 4500
            assert config_capped.merge_policy == "aggressive"
            assert config_capped.lazy_eval_threshold == 50

    def test_public_runtime_export_for_complexity_metrics(self) -> None:
        """Implementation metrics are not promoted through the analysis root."""
        import pysymex

        assert not hasattr(pysymex, "ComplexityMetrics")
