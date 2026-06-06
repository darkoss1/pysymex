"""Focused ``BINARY_SUBSCR`` feasibility fast-path regressions."""

from __future__ import annotations

import pytest
import z3

from pysymex.analysis.detectors import IssueKind
from pysymex.core.solver.engine.results import SolverResult
from pysymex.core.state.record import VMState
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher
from pysymex.execution.opcodes.common.collections.subscript import handle_common_binary_subscr
from tests.unit.execution.opcodes.common.collections_helpers import instr


def test_exact_symbolic_list_index_skips_out_of_bounds_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A proven exact index should not ask whether unrelated OOB indexes are feasible."""
    index, index_constraint = SymbolicValue.symbolic_int("exact_fast_index")
    state = VMState(stack=[SymbolicList.from_const([11, 22, 33]), index], pc=19)
    state = state.add_constraint(index_constraint)
    state = state.add_constraint(index.z3_int == 1)

    def fail_path_is_sat(
        _constraints: list[z3.BoolRef],
        *,
        known_sat_prefix_len: int | None = None,
    ) -> bool:
        _ = known_sat_prefix_len
        raise AssertionError("exact index should avoid the out-of-bounds SAT probe")

    monkeypatch.setattr(
        "pysymex.execution.opcodes.common.collections.read.path_is_sat",
        fail_path_is_sat,
    )

    result = handle_common_binary_subscr(instr("BINARY_SUBSCR"), state, OpcodeDispatcher())

    assert result.new_states[0].stack[-1] == 22


def test_exact_symbolic_list_index_unknown_keeps_symbolic_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Solver UNKNOWN for the current path must not become a concrete list load."""
    index, index_constraint = SymbolicValue.symbolic_int("exact_unknown_index")
    state = VMState(stack=[SymbolicList.from_const([11, 22, 33]), index], pc=19)
    state = state.add_constraint(index_constraint)
    state = state.add_constraint(index.z3_int == 1)

    def unknown_check(
        _constraints: list[z3.BoolRef],
        *,
        known_sat_prefix_len: int | None = None,
    ) -> SolverResult:
        _ = known_sat_prefix_len
        return SolverResult.unknown()

    monkeypatch.setattr(
        "pysymex.execution.opcodes.common.collections.read.check_sat_result",
        unknown_check,
    )

    result = handle_common_binary_subscr(instr("BINARY_SUBSCR"), state, OpcodeDispatcher())

    loaded = result.new_states[0].stack[-1]
    assert isinstance(loaded, SymbolicValue)
    assert loaded.value is None


def test_bounded_symbolic_list_index_skips_exact_false_oob_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A locally in-bounds symbolic index should not call the solver path helper."""
    x = z3.Int("bounded_subscript_x")
    index = SymbolicValue.from_z3((x % 2) + 2, "bounded_subscript_index")
    state = VMState(stack=[SymbolicList.from_const([11, 22, 33, 44]), index], pc=19)

    def fail_path_is_sat(
        _constraints: list[z3.BoolRef],
        *,
        known_sat_prefix_len: int | None = None,
    ) -> bool:
        _ = known_sat_prefix_len
        raise AssertionError("exact false out-of-bounds condition should not call path_is_sat")

    monkeypatch.setattr(
        "pysymex.execution.opcodes.common.collections.read.path_is_sat",
        fail_path_is_sat,
    )

    result = handle_common_binary_subscr(instr("BINARY_SUBSCR"), state, OpcodeDispatcher())

    loaded = result.new_states[0].stack[-1]
    assert isinstance(loaded, SymbolicValue)
    assert loaded.value is None


def test_definite_subscript_exception_skips_success_feasibility_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An exact true exception condition has no feasible success branch to query."""
    state = VMState(stack=[{"present": 1}, "missing"], pc=18)

    def fail_path_is_sat(
        _constraints: list[z3.BoolRef],
        *,
        known_sat_prefix_len: int | None = None,
    ) -> bool:
        _ = known_sat_prefix_len
        raise AssertionError("definite exception should not query success feasibility")

    monkeypatch.setattr(
        "pysymex.execution.opcodes.common.collections.read.path_is_sat",
        fail_path_is_sat,
    )

    result = handle_common_binary_subscr(instr("BINARY_SUBSCR"), state, OpcodeDispatcher())

    assert result.terminal
    assert [issue.kind for issue in result.issues] == [IssueKind.KEY_ERROR]


def test_definite_subscript_exception_on_infeasible_path_has_no_successor() -> None:
    """A definite exception on an UNSAT path must not fall through as a read success."""
    guard = z3.Int("infeasible_definite_subscript_guard")
    state = VMState(
        stack=[{"present": 1}, "missing"],
        path_constraints=[guard > 0, guard < 0],
        pending_constraint_count=2,
        pc=18,
    )

    result = handle_common_binary_subscr(instr("BINARY_SUBSCR"), state, OpcodeDispatcher())

    assert result.terminal
    assert result.new_states == []
    assert result.issues == []


def test_definite_subscript_exception_reuses_inconclusive_path_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Do not re-query a definite exception path already marked inconclusive."""
    guard = z3.Int("inconclusive_definite_subscript_guard")
    state = VMState(
        stack=[{"present": 1}, "missing"],
        path_constraints=[guard > 0],
        last_inconclusive_feasibility_len=1,
        pc=18,
    )

    def fail_check_sat_result(
        _constraints: list[z3.BoolRef],
        *,
        known_sat_prefix_len: int | None = None,
    ) -> SolverResult:
        _ = known_sat_prefix_len
        raise AssertionError("already-inconclusive definite exception should not re-query")

    monkeypatch.setattr(
        "pysymex.execution.opcodes.common.collections.read.check_sat_result",
        fail_check_sat_result,
    )

    result = handle_common_binary_subscr(instr("BINARY_SUBSCR"), state, OpcodeDispatcher())

    assert result.terminal
    assert result.new_states == []
    assert result.issues == []
