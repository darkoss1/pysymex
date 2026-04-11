from __future__ import annotations

from collections.abc import Callable
from types import CodeType

from pysymex.execution.types import ExecutionConfig, ExecutionResult
from pysymex.execution import vm


class _FakeExecutor:
    def __init__(self, config: ExecutionConfig | None = None) -> None:
        self.config = config

    def execute_function(
        self,
        function: Callable[..., object],
        symbolic_args: dict[str, str],
    ) -> ExecutionResult:
        _ = function
        _ = symbolic_args
        return ExecutionResult(function_name="execute_function")

    def execute_code(
        self,
        code: CodeType,
        symbolic_vars: dict[str, str] | None,
        initial_globals: dict[str, object] | None,
    ) -> ExecutionResult:
        _ = code
        _ = symbolic_vars
        _ = initial_globals
        return ExecutionResult(function_name="execute_code")

def test_execute_function() -> None:
    """Test execute_function behavior."""
    original = vm.SymbolicExecutor
    vm.SymbolicExecutor = _FakeExecutor
    try:
        cfg = ExecutionConfig(max_paths=5)

        def sample(value: int) -> int:
            return value + 1

        result = vm.execute_function(sample, {"value": "int"}, cfg)
        assert result.function_name == "execute_function"
    finally:
        vm.SymbolicExecutor = original


def test_execute_code() -> None:
    """Test execute_code behavior."""
    original = vm.SymbolicExecutor
    vm.SymbolicExecutor = _FakeExecutor
    try:
        cfg = ExecutionConfig(max_paths=7)
        code = compile("a = 1\nb = a + 2", "<test>", "exec")
        result = vm.execute_code(code, {"a": "int"}, {}, cfg)
        assert result.function_name == "execute_code"
    finally:
        vm.SymbolicExecutor = original
