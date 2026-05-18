from __future__ import annotations

import dis
from collections.abc import Iterable

import z3

import pysymex.core.solver.engine as solver_mod
from pysymex.analysis.detectors import IssueKind, TypeErrorDetector
from pysymex.core.solver.engine import SolverResult
from pysymex.core.state import VMState, VMStateError
from pysymex.execution.dispatcher import OpcodeResult
from pysymex.execution.executors.core import SymbolicExecutor
from pysymex.execution.strategies.manager import create_path_manager
from pysymex.execution.types import ExecutionConfig
from pysymex.plugins.base import PluginManager


class _IncrementalSensitiveSolver:
    """A fake solver that would misclassify UNSAT if prefix mode were used."""

    def __init__(self) -> None:
        self.prefix_args: list[int | None] = []

    def check(
        self,
        *assumptions: z3.BoolRef,
        need_model: bool = True,
    ) -> SolverResult | z3.CheckSatResult:
        _ = need_model
        solver = z3.Solver()
        solver.add(*assumptions)
        if solver.check() == z3.sat:
            return SolverResult.sat(solver.model())
        return SolverResult.unsat()

    def push(self) -> None:
        return None

    def pop(self) -> None:
        return None

    def add(self, *constraints: z3.BoolRef) -> None:
        _ = constraints

    def reset(self) -> None:
        self.prefix_args = []

    def is_sat(
        self,
        constraints: Iterable[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> bool:
        self.prefix_args.append(known_sat_prefix_len)
        if known_sat_prefix_len is not None:
            return True
        exprs = list(constraints)
        solver = z3.Solver()
        solver.add(*exprs)
        return solver.check() == z3.sat

    def check_sat_result(
        self,
        constraints: Iterable[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> SolverResult:
        return (
            SolverResult.sat(None)
            if self.is_sat(constraints, known_sat_prefix_len)
            else SolverResult.unsat()
        )

    def get_model(self, constraints: list[z3.BoolRef]) -> z3.ModelRef | None:
        solver = z3.Solver()
        solver.add(*constraints)
        if solver.check() != z3.sat:
            return None
        return solver.model()

    def get_stats(self) -> dict[str, object]:
        return {}

    def constraint_optimizer(self) -> object:
        return self

    def set_deadline(self, deadline_time: float | None) -> None:
        _ = deadline_time


class _UnknownSolver(_IncrementalSensitiveSolver):
    """A solver double that models Z3 timeout/unknown for detector feasibility."""

    def is_sat(
        self,
        constraints: Iterable[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> bool:
        _ = constraints
        self.prefix_args.append(known_sat_prefix_len)
        return True

    def check_sat_result(
        self,
        constraints: Iterable[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> SolverResult:
        _ = list(constraints)
        self.prefix_args.append(known_sat_prefix_len)
        return SolverResult.unknown()


def _simple(x: int) -> int:
    if x > 0:
        return x + 1
    return x - 1


def _caught_zero_division(x: int) -> int:
    try:
        return 10 // x
    except ZeroDivisionError:
        return 0


def _caught_zero_division_rebinds_before_assert(x: int) -> int:
    try:
        _ = 10 // x
    except ZeroDivisionError:
        x = 1
    assert x != 0
    return x


def _wrong_handler_zero_division(x: int) -> int:
    try:
        return 10 // x
    except ValueError:
        return 0


def _tuple_handler_zero_division(x: int) -> int:
    try:
        return 10 // x
    except (ZeroDivisionError, ValueError):
        return 0


def _try_finally_zero_division_uncaught(x: int) -> int:
    value = 0
    try:
        value = 10 // x
    finally:
        value += 1
    return value


def _try_finally_zero_division_guarded(x: int) -> int:
    value = 0
    try:
        if x != 0:
            value = 10 // x
    finally:
        value += 1
    return value


def _bounded_while_post_loop_assertion(x: int) -> int:
    total = 0
    step = 0
    while step < 3:
        total += step
        step += 1
    if x == total:
        assert x != 3
    return total


def _uncaught_runtime_error(flag: bool) -> int:
    if flag:
        raise RuntimeError("boom")
    return 0


def _caught_runtime_error(flag: bool) -> int:
    try:
        if flag:
            raise RuntimeError("boom")
    except RuntimeError:
        return 1
    return 0


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

    def test_detector_query_cache_reuses_exact_constraint_query(self) -> None:
        """Repeated detector queries with identical formulas should hit executor cache."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=2, max_iterations=20))
        x = z3.Int("detector_cache_x")

        assert executor._detector_is_sat([x > 0], 0) is True  # type: ignore[reportPrivateUsage]  # white-box test validates detector-query SSoT cache
        assert executor._detector_is_sat([x > 0], 0) is True  # type: ignore[reportPrivateUsage]  # white-box test validates detector-query SSoT cache

        stats = executor._collect_detector_query_stats()  # type: ignore[reportPrivateUsage]  # white-box test validates detector-query SSoT cache
        assert stats["cache_misses"] == 1
        assert stats["cache_hits"] == 1

    def test_detector_query_cache_collision_falls_back_to_solver(self) -> None:
        """Hash collisions must not reuse SAT results for different formulas."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=2, max_iterations=20))

        def forced_cache_key(constraints: list[z3.BoolRef]) -> int:
            _ = constraints
            return 1

        setattr(executor, "_detector_query_cache_key", forced_cache_key)
        x = z3.Int("detector_collision_x")
        y = z3.Int("detector_collision_y")

        assert executor._detector_is_sat([x > 0, x < 0], 0) is False  # type: ignore[reportPrivateUsage]  # white-box test seeds a collision bucket through the detector-query SSoT
        assert executor._detector_is_sat([y > 0], 0) is True  # type: ignore[reportPrivateUsage]  # white-box test validates collision-safe detector-query lookup

        stats = executor._collect_detector_query_stats()  # type: ignore[reportPrivateUsage]  # white-box test validates detector-query SSoT cache
        assert stats["cache_misses"] == 2
        assert stats["cache_hits"] == 0

    def test_detector_feasibility_uses_full_constraints_not_prefix(self) -> None:
        """Detector bug reports require full-path feasibility, not suffix-only SAT."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=2, max_iterations=20))
        sensitive_solver = _IncrementalSensitiveSolver()
        executor.solver = sensitive_solver
        x = z3.Int("detector_full_path_x")

        result = executor._detector_is_sat([x > 0, x < 0], 1)  # type: ignore[reportPrivateUsage]  # white-box test validates detector feasibility soundness

        assert result is False
        assert sensitive_solver.prefix_args == [None]

    def test_execute_loop_restores_outer_active_solver_context(self) -> None:
        """Nested executor loops must not erase an existing active solver context."""
        outer_solver = _IncrementalSensitiveSolver()
        executor = SymbolicExecutor(ExecutionConfig(max_paths=2, max_iterations=20))
        executor._worklist = create_path_manager(executor.config.strategy)  # type: ignore[reportPrivateUsage]  # white-box test validates active solver context restoration

        token = solver_mod.active_incremental_solver.set(outer_solver)
        try:
            executor._execute_loop()  # type: ignore[reportPrivateUsage]  # white-box test validates active solver context restoration
            active_solver = solver_mod.active_incremental_solver.get()
        finally:
            solver_mod.active_incremental_solver.reset(token)

        assert active_solver is outer_solver

    def test_execute_step_converts_vm_state_error_to_unknown_issue(self) -> None:
        """Internal VM stack failures should terminate the path as UNKNOWN, not crash scans."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=2, max_iterations=20))
        code = compile("x = 1", "<vm-state-error-test>", "exec")
        executor._instructions = list(dis.get_instructions(code))  # type: ignore[reportPrivateUsage]  # white-box test seeds active bytecode
        state = VMState(pc=0)

        def fail_dispatch(instr: dis.Instruction, state: VMState) -> OpcodeResult:
            _ = instr
            _ = state
            raise VMStateError("unit stack failure")

        executor.dispatcher.dispatch = fail_dispatch  # type: ignore[method-assign]

        executor._execute_step(state)  # type: ignore[reportPrivateUsage]  # white-box test validates executor crash boundary

        assert executor._issues[-1].kind is IssueKind.UNKNOWN  # type: ignore[reportPrivateUsage]
        assert "unit stack failure" in executor._issues[-1].message  # type: ignore[reportPrivateUsage]
        assert executor._paths_pruned == 1  # type: ignore[reportPrivateUsage]

    def test_partition_chtd_unsat_uses_full_constraints(self) -> None:
        """CHTD UNSAT validation must not rely on known SAT prefix lengths."""
        executor = SymbolicExecutor(
            ExecutionConfig(max_paths=4, max_iterations=40, enable_chtd=True)
        )
        sensitive_solver = _IncrementalSensitiveSolver()
        executor.solver = sensitive_solver

        x = z3.Int("x")
        parent = VMState(path_constraints=[x > 0], pc=1)
        contradictory = VMState(path_constraints=[x > 0, x < 0], pc=2)

        unsat_states, sat_states = executor._partition_chtd_unsat(  # type: ignore[reportPrivateUsage]  # white-box test requires access to internal state
            parent_state=parent,
            forked_states=[contradictory],
        )

        assert unsat_states == [contradictory]
        assert sat_states == []
        assert executor._chtd_unsat_mismatches == 0  # type: ignore[reportPrivateUsage]  # white-box test requires access to internal state
        assert sensitive_solver.prefix_args == [None]

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

        unsat_states, sat_states = executor._partition_chtd_unsat(  # type: ignore[reportPrivateUsage]  # white-box test requires access to internal state
            parent_state=parent,
            forked_states=[unsat_candidate, sat_candidate],
        )

        assert unsat_states == [unsat_candidate]
        assert sat_states == [sat_candidate]
        assert executor._chtd_unsat_mismatches == 1  # type: ignore[reportPrivateUsage]  # white-box test requires access to internal state

    def test_check_path_feasibility_prunes_on_certified_core_containment(self) -> None:
        """Certified core containment should prune before issuing another solver query."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=4, max_iterations=40))
        sensitive_solver = _IncrementalSensitiveSolver()
        executor.solver = sensitive_solver
        x = z3.Int("certified_core_prune_x")
        left = x > 0
        right = x < 0
        state = VMState(path_constraints=[left, right], pc=2)

        assert executor.core_registry.add_core([left.hash(), right.hash()]) is True

        result = executor._check_path_feasibility(state)  # type: ignore[reportPrivateUsage]  # white-box test validates certified-core pruning

        assert result is False
        assert executor._paths_pruned == 1  # type: ignore[reportPrivateUsage]  # white-box test validates pruning counter
        assert sensitive_solver.prefix_args == []

    def test_accelerator_only_unsat_candidate_is_not_pruned_without_validation(self) -> None:
        """CHTD/acceleration UNSAT candidates are kept when full solver validation says SAT."""
        executor = SymbolicExecutor(
            ExecutionConfig(max_paths=4, max_iterations=40, enable_chtd=True)
        )
        executor.solver = _IncrementalSensitiveSolver()
        y = z3.Int("accel_candidate_sat_y")
        parent = VMState(path_constraints=[], pc=1)
        accelerator_unsat_candidate = VMState(path_constraints=[y > 1, y < 5], pc=2)

        unsat_states, sat_states = executor._partition_chtd_unsat(  # type: ignore[reportPrivateUsage]  # white-box test validates acceleration validation boundary
            parent_state=parent,
            forked_states=[accelerator_unsat_candidate],
        )

        assert unsat_states == []
        assert sat_states == [accelerator_unsat_candidate]
        assert executor.core_registry.num_cores == 0
        assert executor._chtd_unsat_mismatches == 1  # type: ignore[reportPrivateUsage]  # white-box test validates validation mismatch telemetry

    def test_detector_feasibility_unknown_is_not_reportable_sat(self) -> None:
        """Detector feasibility must not turn solver UNKNOWN into definite SAT."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=2, max_iterations=20))
        unknown_solver = _UnknownSolver()
        executor.solver = unknown_solver
        x = z3.Int("detector_unknown_x")

        result = executor._detector_is_sat([x > 0], 0)  # type: ignore[reportPrivateUsage]  # white-box test validates detector feasibility soundness

        assert result is False
        assert executor._degraded_passes == ["solver_unknown_detector_query"]  # type: ignore[reportPrivateUsage]  # white-box test validates diagnostic propagation
        assert unknown_solver.prefix_args == [None]

    def test_caught_zero_division_handler_suppresses_uncaught_detector_issue(self) -> None:
        """A matching CPython exception-table handler means the division is not uncaught."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=4, max_iterations=40))

        result = executor.execute_function(_caught_zero_division, {"x": "int"})

        assert all(issue.kind != IssueKind.DIVISION_BY_ZERO for issue in result.issues)

    def test_caught_zero_division_handler_rebinding_feeds_post_try_assertion(self) -> None:
        """Caught division paths should continue through the handler with updated locals."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=8, max_iterations=120))

        result = executor.execute_function(
            _caught_zero_division_rebinds_before_assert,
            {"x": "int"},
        )

        assert all(issue.kind != IssueKind.DIVISION_BY_ZERO for issue in result.issues)
        assert all(issue.kind != IssueKind.ASSERTION_ERROR for issue in result.issues)

    def test_wrong_exception_handler_preserves_division_by_zero_issue(self) -> None:
        """A protected opcode is still reportable when the handler type does not match."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=4, max_iterations=40))

        result = executor.execute_function(_wrong_handler_zero_division, {"x": "int"})

        assert any(issue.kind == IssueKind.DIVISION_BY_ZERO for issue in result.issues)

    def test_tuple_exception_handler_suppresses_division_by_zero_issue(self) -> None:
        """Tuple exception handlers should suppress caught ZeroDivisionError paths."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=4, max_iterations=40))

        result = executor.execute_function(_tuple_handler_zero_division, {"x": "int"})

        assert all(issue.kind != IssueKind.DIVISION_BY_ZERO for issue in result.issues)

    def test_try_finally_cleanup_does_not_suppress_uncaught_zero_division(self) -> None:
        """A finally cleanup runs before propagation but does not catch ZeroDivisionError."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=8, max_iterations=120))

        result = executor.execute_function(_try_finally_zero_division_uncaught, {"x": "int"})

        assert any(issue.kind == IssueKind.DIVISION_BY_ZERO for issue in result.issues)

    def test_try_finally_guard_prevents_zero_division_issue(self) -> None:
        """A nonzero guard inside try/finally should still prevent division bugs."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=8, max_iterations=120))

        result = executor.execute_function(_try_finally_zero_division_guarded, {"x": "int"})

        assert all(issue.kind != IssueKind.DIVISION_BY_ZERO for issue in result.issues)

    def test_state_merging_preserves_bounded_while_post_loop_assertion(self) -> None:
        """Loop headers should not be merged in a way that hides accumulated locals."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=16, max_iterations=240))

        result = executor.execute_function(_bounded_while_post_loop_assertion, {"x": "int"})

        assert any(issue.kind == IssueKind.ASSERTION_ERROR for issue in result.issues)

    def test_uncaught_runtime_error_reports_unhandled_exception(self) -> None:
        """Explicit RuntimeError raises are reported when no handler catches them."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=4, max_iterations=40))

        result = executor.execute_function(_uncaught_runtime_error, {"flag": "bool"})

        assert any(issue.kind == IssueKind.UNHANDLED_EXCEPTION for issue in result.issues)

    def test_caught_runtime_error_suppresses_unhandled_exception(self) -> None:
        """Matching exception-table handlers suppress explicit RuntimeError reports."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=4, max_iterations=40))

        result = executor.execute_function(_caught_runtime_error, {"flag": "bool"})

        assert all(issue.kind != IssueKind.UNHANDLED_EXCEPTION for issue in result.issues)
