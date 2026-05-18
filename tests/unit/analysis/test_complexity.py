from pysymex.analysis.complexity import (
    ComplexityAnalysis,
    ComplexityMetrics,
    analyze_complexity,
    estimate_complexity,
    tune_execution_config,
)
from pysymex.execution.types import ExecutionConfig


class TestComplexityAnalysis:
    """Test suite for pysymex.analysis.complexity."""

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

    def test_estimate_complexity(self) -> None:
        """Test backward-compatibility wrapper."""

        def dummy_func() -> None:
            pass

        code = dummy_func.__code__
        result = estimate_complexity(code)
        validated_result: ComplexityAnalysis = result
        assert validated_result["complexity_score"] >= 0
        assert "recommended_timeout_ms" in result
        assert result["total_instructions"] > 0

    def test_tune_execution_config(self) -> None:
        """Test tune_execution_config behavior."""

        def dummy_func() -> None:
            pass

        code = dummy_func.__code__
        base_config = ExecutionConfig()
        config = tune_execution_config(code, base_config)
        assert isinstance(config, ExecutionConfig)
        assert config.max_paths <= 100

    def test_public_runtime_export_for_complexity_analysis(self) -> None:
        """Test lazy runtime export is available from pysymex.analysis."""
        from pysymex.analysis import ComplexityAnalysis as ExportedComplexityAnalysis

        assert ExportedComplexityAnalysis is ComplexityAnalysis
