from __future__ import annotations

import dis

from pysymex.analysis.detectors import TypeErrorDetector
from pysymex.core.state import VMState
from pysymex.execution.dispatcher import OpcodeResult
from pysymex.execution.executors.core import SymbolicExecutor
from pysymex.execution.types import ExecutionConfig
from pysymex.plugins.base import PluginManager


def _simple(x: int) -> int:
    if x > 0:
        return x + 1
    return x - 1

class TestSymbolicExecutor:
    """Test suite for pysymex.execution.executors.core.SymbolicExecutor."""
    def test_add_detector(self) -> None:
        """Test add_detector behavior."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=4, max_iterations=40))
        detector = TypeErrorDetector()
        executor.add_detector(detector)
        result = executor.execute_function(_simple, {"x": "int"})
        assert result.paths_explored >= 1

    def test_register_handler(self) -> None:
        """Test register_handler behavior."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=2, max_iterations=20))

        def local_handler(
            instr: dis.Instruction,
            state: VMState,
            ctx: object,
        ) -> OpcodeResult:
            _ = instr
            _ = ctx
            return OpcodeResult.continue_with(state.advance_pc())

        executor.register_handler("UNIT_TEST_OPCODE", local_handler)
        assert executor.dispatcher.has_handler("UNIT_TEST_OPCODE") is True

    def test_register_hook(self) -> None:
        """Test register_hook behavior."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=2, max_iterations=20))
        seen = {"count": 0}

        def hook(*args: object, **kwargs: object) -> None:
            _ = args
            _ = kwargs
            seen["count"] += 1

        executor.register_hook("pre_step", hook)
        _ = executor.execute_function(_simple, {"x": "int"})
        assert seen["count"] >= 1

    def test_load_plugins(self) -> None:
        """Test load_plugins behavior."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=2, max_iterations=20))

        manager = PluginManager()
        executor.load_plugins(manager)
        assert manager.list_plugins() == []

    def test_execute_function(self) -> None:
        """Test execute_function behavior."""
        executor = SymbolicExecutor(
            ExecutionConfig(max_paths=8, max_iterations=80, timeout_seconds=5.0)
        )
        result = executor.execute_function(_simple, {"x": "int"})
        assert result.function_name == "_simple"
        assert result.paths_explored >= 1

    def test_execute_code(self) -> None:
        """Test execute_code behavior."""
        executor = SymbolicExecutor(
            ExecutionConfig(max_paths=8, max_iterations=80, timeout_seconds=5.0)
        )
        code = compile("x = 1\ny = x + 2", "<test>", "exec")
        result = executor.execute_code(code, {"x": "int"}, {"x": 1})
        assert result.source_file == "<test>"
        assert result.paths_explored >= 1
