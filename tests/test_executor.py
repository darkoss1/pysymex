"""Tests for executor core (hooks, plugins, protocol compliance)."""

from __future__ import annotations

from pysymex.analysis.detectors.protocols import ExecutionContextLike
from pysymex.execution.executor_core import SymbolicExecutor
from pysymex.execution.executor_types import ExecutionConfig


class TestExecutionContextProtocol:
    """Verify SymbolicExecutor satisfies ExecutionContextLike."""

    def test_executor_is_execution_context_like(self) -> None:
        executor = SymbolicExecutor()
        assert isinstance(executor, ExecutionContextLike)

    def test_executor_has_register_hook(self) -> None:
        executor = SymbolicExecutor()
        assert callable(getattr(executor, "register_hook", None))

    def test_register_hook_stores_handler(self) -> None:
        executor = SymbolicExecutor()
        calls: list[object] = []
        executor.register_hook("pre_step", lambda *a: calls.append(a))
        assert len(executor._hooks["pre_step"]) == 1


class TestExecutorBasic:
    """Smoke tests for SymbolicExecutor creation and simple execution."""

    def test_create_default(self) -> None:
        executor = SymbolicExecutor()
        assert executor.config is not None
        assert executor.solver is not None

    def test_create_with_config(self) -> None:
        cfg = ExecutionConfig(max_paths=50, max_depth=10)
        executor = SymbolicExecutor(config=cfg)
        assert executor.config.max_paths == 50

    def test_execute_identity(self) -> None:
        executor = SymbolicExecutor()

        def identity(x):
            return x

        result = executor.execute_function(identity, {"x": "int"})
        assert result.paths_explored >= 1
        assert result.function_name == "identity"
