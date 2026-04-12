
from pysymex.analysis.autotuner import CodeComplexity, AutoTuner
from pysymex.execution.executors import ExecutionConfig

class TestCodeComplexity:
    """Test suite for pysymex.analysis.autotuner.CodeComplexity."""
    def test_score(self) -> None:
        """Test score behavior."""
        comp = CodeComplexity(instruction_count=10, branch_count=2, loop_count=1, cyclomatic_complexity=3)
        assert comp.score == 10 + (2 * 5) + (1 * 10)

class TestAutoTuner:
    """Test suite for pysymex.analysis.autotuner.AutoTuner."""
    def test_analyze(self) -> None:
        """Test analyze behavior."""
        def dummy_func() -> None:
            for i in range(10):
                if i > 5:
                    pass
        code = dummy_func.__code__
        comp = AutoTuner.analyze(code)
        assert comp.instruction_count > 0
        assert comp.branch_count >= 0
        assert comp.loop_count >= 0

    def test_tune(self) -> None:
        """Test tune behavior."""
        def dummy_func() -> None:
            pass
        code = dummy_func.__code__
        config = AutoTuner.tune(code)
        assert isinstance(config, ExecutionConfig)
