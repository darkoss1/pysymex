from __future__ import annotations

import dis
import z3

from pysymex.analysis.detectors import TypeErrorDetector
from pysymex.core.state import VMState
from pysymex.execution.dispatcher import OpcodeResult
from pysymex.execution.executors.core import SymbolicExecutor
from pysymex.execution.types import ExecutionConfig
from pysymex.plugins.base import PluginManager


class _IncrementalSensitiveSolver:
    """A fake solver that would misclassify UNSAT if prefix mode were used."""

    def __init__(self) -> None:
        self.prefix_args: list[int | None] = []

    def is_sat(self, constraints: object, known_sat_prefix_len: int | None = None) -> bool:
        self.prefix_args.append(known_sat_prefix_len)
        if known_sat_prefix_len is not None:
            return True
        if hasattr(constraints, "to_list"):
            exprs = constraints.to_list()
        else:
            exprs = list(constraints)
        solver = z3.Solver()
        solver.add(*exprs)
        return solver.check() == z3.sat


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

    def test_partition_chtd_unsat_uses_full_constraints(self) -> None:
        """CHTD UNSAT validation must not rely on known SAT prefix lengths."""
        executor = SymbolicExecutor(
            ExecutionConfig(max_paths=4, max_iterations=40, enable_chtd=True)
        )
        executor.solver = _IncrementalSensitiveSolver()

        x = z3.Int("x")
        parent = VMState(path_constraints=[x > 0], pc=1)
        contradictory = VMState(path_constraints=[x > 0, x < 0], pc=2)

        unsat_states, sat_states = executor._partition_chtd_unsat(
            parent_state=parent,
            forked_states=[contradictory],
        )

        assert unsat_states == [contradictory]
        assert sat_states == []
        assert executor._chtd_unsat_mismatches == 0
        assert executor.solver.prefix_args == [None]

    def test_partition_chtd_unsat_splits_sat_and_unsat_correctly(self) -> None:
        """CHTD partitioning should preserve SAT candidates and prune only UNSAT ones."""
        executor = SymbolicExecutor(
            ExecutionConfig(max_paths=4, max_iterations=40, enable_chtd=True)
        )
        executor.solver = _IncrementalSensitiveSolver()

        x = z3.Int("x")
        y = z3.Int("y")
        parent = VMState(path_constraints=[x >= 0], pc=1)
        unsat_candidate = VMState(path_constraints=[x >= 0, x < 0], pc=2)
        sat_candidate = VMState(path_constraints=[y > 1, y < 5], pc=3)

        unsat_states, sat_states = executor._partition_chtd_unsat(
            parent_state=parent,
            forked_states=[unsat_candidate, sat_candidate],
        )

        assert unsat_states == [unsat_candidate]
        assert sat_states == [sat_candidate]
        assert executor._chtd_unsat_mismatches == 1
