from __future__ import annotations

from pysymex.execution.executors.concurrent import (
    ConcurrentSymbolicExecutor,
    SharedVariableTracker,
    analyze_concurrent,
)
from pysymex.execution.types import ExecutionConfig

class TestSharedVariableTracker:
    """Test suite for pysymex.execution.executors.concurrent.SharedVariableTracker."""
    def test_record_access(self) -> None:
        """Test record_access behavior."""
        tracker = SharedVariableTracker()
        tracker.record_access("t1", "x", is_write=True)
        tracker.record_access("t2", "x", is_write=False)
        assert tracker.is_shared("x") is True

    def test_get_shared_variables(self) -> None:
        """Test get_shared_variables behavior."""
        tracker = SharedVariableTracker()
        tracker.record_access("t1", "a")
        tracker.record_access("t2", "a")
        shared = tracker.get_shared_variables()
        assert "a" in shared

    def test_is_shared(self) -> None:
        """Test is_shared behavior."""
        tracker = SharedVariableTracker()
        tracker.record_access("t1", "k")
        assert tracker.is_shared("k") is False

    def test_reset(self) -> None:
        """Test reset behavior."""
        tracker = SharedVariableTracker()
        tracker.record_access("t1", "x")
        tracker.record_access("t2", "x")
        tracker.reset()
        assert tracker.get_shared_variables() == set()


class TestConcurrentSymbolicExecutor:
    """Test suite for pysymex.execution.executors.concurrent.ConcurrentSymbolicExecutor."""
    def test_execute_function(self) -> None:
        """Test execute_function behavior."""
        def sample(x: int) -> int:
            return x + 1

        executor = ConcurrentSymbolicExecutor(
            ExecutionConfig(max_paths=4, max_iterations=40, enable_concurrency_analysis=True)
        )
        result = executor.execute_function(sample, {"x": "int"})
        assert result.function_name == "sample"


def test_analyze_concurrent() -> None:
    """Test analyze_concurrent behavior."""
    def sample(x: int) -> int:
        return x * 2

    result = analyze_concurrent(sample, {"x": "int"}, max_paths=3, max_iterations=30)
    assert result.function_name == "sample"
