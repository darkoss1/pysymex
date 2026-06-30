"""Tests for core executor handler and extension hook APIs."""

from __future__ import annotations

import dis

from pysymex._internal.config.execution.settings import ExecutionConfig
from pysymex._internal.core.state.record import VMState
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.executors.core import SymbolicExecutor
from tests.unit.execution.executors.core_executor_helpers import simple


class TestSymbolicExecutorHooks:
    """Handler registration and extension hook behavior."""

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
        _ = executor.execute_function(simple, {"x": "int"})
        assert seen["count"] >= 1

    def test_post_step_hook_observes_successor_states(self) -> None:
        """Post-step hooks still receive successor states after the no-hook fast path."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=4, max_iterations=40))
        seen_successor_pcs: list[int] = []

        def hook(
            _executor: SymbolicExecutor,
            next_state: VMState,
            _instruction: dis.Instruction,
        ) -> None:
            seen_successor_pcs.append(next_state.pc)

        executor.register_hook("post_step", hook)
        result = executor.execute_function(simple, {"x": "int"})

        assert result.paths_explored >= 1
        assert seen_successor_pcs

    def test_execute_step_calls_before_dispatch_extension_hook(self) -> None:
        """Executor variants can intercept a step without copying the core loop."""

        class HookedExecutor(SymbolicExecutor):
            def __init__(self) -> None:
                super().__init__(ExecutionConfig(max_paths=2, max_iterations=20))
                self.seen: list[str] = []

            def _before_dispatch(
                self,
                instr: dis.Instruction,
                state: VMState,
                active_instructions: list[dis.Instruction],
            ) -> None:
                _ = state
                _ = active_instructions
                self.seen.append(instr.opname)

        executor = HookedExecutor()
        result = executor.execute_function(simple, {"x": "int"})

        assert result.function_name == "simple"
        assert executor.seen

    def test_execute_step_calls_path_complete_extension_hook(self) -> None:
        """Executor variants can observe normal path completion."""

        class HookedExecutor(SymbolicExecutor):
            def __init__(self) -> None:
                super().__init__(ExecutionConfig(max_paths=2, max_iterations=20))
                self.completed = 0

            def _on_path_complete(self, state: VMState) -> None:
                _ = state
                self.completed += 1

        executor = HookedExecutor()
        result = executor.execute_function(simple, {"x": "int"})

        assert result.paths_completed >= 1
        assert executor.completed == result.paths_completed
