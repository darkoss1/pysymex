from pysymex.analysis.scan.complexity import (
    ComplexityMetrics,
    analyze_complexity,
    recommended_timeout_ms,
    tune_execution_config,
)
from pysymex.execution.config.settings import ExecutionConfig


class TestComplexityMetrics:
    """Test suite for pysymex.analysis.scan.complexity."""

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

    def test_tune_execution_config(self) -> None:
        """Test tune_execution_config behavior."""

        def dummy_func() -> None:
            pass

        code = dummy_func.__code__
        base_config = ExecutionConfig()
        config = tune_execution_config(code, base_config)
        assert isinstance(config, ExecutionConfig)
        assert config.max_paths <= 100

    def test_public_runtime_export_for_complexity_metrics(self) -> None:
        """Test lazy runtime export is available from pysymex.analysis."""
        from pysymex.analysis import ComplexityMetrics as ExportedComplexityMetrics

        assert ExportedComplexityMetrics is ComplexityMetrics
