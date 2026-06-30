"""Focused tests for index bounds detector primitives."""

from __future__ import annotations

import time

import pytest
import z3

from pysymex._internal.analysis.detectors.runtime.indexing.bounds.core import (
    pure_check_index_bounds,
    pure_check_index_bounds_result,
)
from pysymex._internal.analysis.detectors.runtime.indexing.bounds.types import (
    IndexBoundsCheckStatus,
)
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.solver.engine.context import SolverContext
from pysymex._internal.core.solver.engine.incremental import IncrementalSolver
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.value.scalar_ops import ScalarValueOps
from pysymex._internal.core.types.scalars.values import SymbolicValue


def _is_sat(constraints: list[z3.BoolRef]) -> bool:
    solver = z3.Solver()
    solver.add(*constraints)
    return solver.check() == z3.sat


def test_pure_check_index_bounds_skips_solver_for_definite_in_bounds_access() -> None:
    """Concrete in-bounds list accesses are not solver queries."""
    container = SymbolicList.from_const([1, 2, 3])
    index = SymbolicValue.from_const(1)

    def fail_if_called(_constraints: list[z3.BoolRef]) -> bool:
        raise AssertionError("in-bounds access should not query the solver")

    issue = pure_check_index_bounds(container, index, [], 7, is_satisfiable_fn=fail_if_called)
    result = pure_check_index_bounds_result(
        container,
        index,
        [],
        7,
        is_satisfiable_fn=fail_if_called,
    )

    assert issue is None
    assert result.status is IndexBoundsCheckStatus.IN_BOUNDS
    assert result.reason == "definitely_in_bounds"
    assert result.issue is None


def test_pure_check_index_bounds_uses_symbolic_constant_payload_without_z3(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    container = [1, 2, 3]
    index = SymbolicValue.from_const(1)

    def fail_simplify(_expr: z3.ExprRef) -> z3.ExprRef:
        raise AssertionError("concrete payload should avoid Z3 simplification")

    monkeypatch.setattr(z3, "simplify", fail_simplify)

    result = pure_check_index_bounds_result(container, index, [], 7)

    assert result.status is IndexBoundsCheckStatus.IN_BOUNDS
    assert result.reason == "definitely_in_bounds"
    assert result.issue is None


def test_pure_check_index_bounds_simplifies_definite_in_bounds_index() -> None:
    """Simplifiable integer index expressions use the no-query in-bounds path."""
    container = SymbolicList.from_const([1, 2, 3])
    index = SymbolicValue(
        _name="one_plus_one",
        z3_int=z3.IntVal(1) + z3.IntVal(1),
        is_int=z3.BoolVal(True),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
        affinity_type="int",
    )

    def fail_if_called(_constraints: list[z3.BoolRef]) -> bool:
        raise AssertionError("simplified in-bounds access should not query the solver")

    result = pure_check_index_bounds_result(
        container,
        index,
        [],
        8,
        is_satisfiable_fn=fail_if_called,
    )

    assert result.status is IndexBoundsCheckStatus.IN_BOUNDS
    assert result.reason == "definitely_in_bounds"
    assert result.issue is None


def test_pure_check_index_bounds_skips_solver_for_positive_modulo_index() -> None:
    """Modulo by a positive divisor has a CPython-compatible nonnegative range."""
    pivot = z3.Int("modulo_index_pivot")
    container = SymbolicList.from_const([1, 2, 3, 4, 5])
    index = SymbolicValue.from_z3(pivot % 5, "pivot%5")

    def fail_if_called(_constraints: list[z3.BoolRef]) -> bool:
        raise AssertionError("positive modulo range should prove the index in-bounds")

    result = pure_check_index_bounds_result(
        container,
        index,
        [],
        9,
        is_satisfiable_fn=fail_if_called,
    )

    assert result.status is IndexBoundsCheckStatus.IN_BOUNDS
    assert result.reason == "definitely_in_bounds"
    assert result.issue is None


def test_pure_check_index_bounds_skips_solver_for_shifted_positive_modulo_index() -> None:
    pivot = z3.Int("shifted_modulo_index_pivot")
    container = SymbolicList.from_const([1, 2, 3, 4, 5])
    index = SymbolicValue.from_z3((pivot % 3) + 2, "pivot%3+2")

    def fail_if_called(_constraints: list[z3.BoolRef]) -> bool:
        raise AssertionError("shifted positive modulo range should prove the index in-bounds")

    result = pure_check_index_bounds_result(
        container,
        index,
        [],
        10,
        is_satisfiable_fn=fail_if_called,
    )

    assert result.status is IndexBoundsCheckStatus.IN_BOUNDS
    assert result.reason == "definitely_in_bounds"
    assert result.issue is None


def test_pure_check_index_bounds_skips_solver_for_pysymex_python_modulo_encoding() -> None:
    pivot = z3.Int("python_modulo_index_pivot")
    container = SymbolicList.from_const([1, 2, 3, 4, 5])
    index = SymbolicValue.from_z3(
        ScalarValueOps.py_mod(pivot, ConstraintValues.int(5)), "py_mod_pivot_5"
    )

    def fail_if_called(_constraints: list[z3.BoolRef]) -> bool:
        raise AssertionError("Python modulo encoding should prove the index in-bounds")

    result = pure_check_index_bounds_result(
        container,
        index,
        [],
        10,
        is_satisfiable_fn=fail_if_called,
    )

    assert result.status is IndexBoundsCheckStatus.IN_BOUNDS
    assert result.reason == "definitely_in_bounds"
    assert result.issue is None


def test_pure_check_index_bounds_reports_shifted_modulo_that_can_escape_bounds() -> None:
    pivot = z3.Int("escaping_modulo_index_pivot")
    container = SymbolicList.from_const([1, 2, 3, 4, 5])
    index = SymbolicValue.from_z3((pivot % 3) + 4, "pivot%3+4")

    result = pure_check_index_bounds_result(
        container,
        index,
        [],
        10,
        is_satisfiable_fn=_is_sat,
    )

    assert result.status is IndexBoundsCheckStatus.OUT_OF_BOUNDS
    assert result.issue is not None


def test_pure_check_index_bounds_result_reports_out_of_bounds() -> None:
    container = SymbolicList.from_const([1, 2, 3])
    index = SymbolicValue.from_const(5)

    result = pure_check_index_bounds_result(container, index, [], 11)

    assert result.status is IndexBoundsCheckStatus.OUT_OF_BOUNDS
    assert result.has_issue
    assert result.issue is not None
    assert result.issue.pc == 11
    assert pure_check_index_bounds(container, index, [], 11) is not None


def test_pure_check_index_bounds_result_reports_no_oob_evidence() -> None:
    container = SymbolicList.from_const([1, 2, 3])
    index, index_constraint = SymbolicValue.symbolic_int("guarded_index")
    constraints = [index_constraint, index.z3_int >= 0, index.z3_int < 3]

    result = pure_check_index_bounds_result(
        container,
        index,
        constraints,
        12,
        is_satisfiable_fn=_is_sat,
    )

    assert result.status is IndexBoundsCheckStatus.NO_OUT_OF_BOUNDS_EVIDENCE
    assert result.reason == "dependency_slice_proves_in_bounds"
    assert result.issue is None


def test_pure_check_index_bounds_result_reports_solver_unknown() -> None:
    container = SymbolicList.from_const([1, 2, 3])
    index, index_constraint = SymbolicValue.symbolic_int("unknown_bounds_result_index")
    solver = IncrementalSolver(timeout_ms=1000)
    solver.set_deadline(time.perf_counter() - 1.0)
    token = SolverContext.active.set(solver)
    try:
        result = pure_check_index_bounds_result(
            container,
            index,
            [index_constraint],
            13,
            is_satisfiable_fn=lambda _constraints: True,
        )
    finally:
        SolverContext.active.reset(token)

    assert result.status is IndexBoundsCheckStatus.INCONCLUSIVE
    assert result.reason == "model_result_unknown"
    assert result.issue is not None
    assert "Path feasibility inconclusive" in result.issue.message
    assert result.issue.model is None
    assert result.issue.get_counterexample() == {}
    assert result.issue.confidence == 0.5


def test_pure_check_index_bounds_result_uses_witness_before_missing_model() -> None:
    container = SymbolicList.from_const([1, 2, 3])
    index, index_constraint = SymbolicValue.symbolic_int("missing_model_index")

    def missing_model(_constraints: list[z3.BoolRef]) -> None:
        return None

    result = pure_check_index_bounds_result(
        container,
        index,
        [index_constraint],
        14,
        is_satisfiable_fn=lambda _constraints: True,
        get_model_fn=missing_model,
    )

    assert result.status is IndexBoundsCheckStatus.OUT_OF_BOUNDS
    assert result.reason is None
    assert result.issue is not None
    assert result.issue.model is not None
    assert result.issue.confidence == 0.9


def test_pure_check_index_bounds_result_reports_unsupported_container() -> None:
    index, index_constraint = SymbolicValue.symbolic_int("unsupported_index")

    result = pure_check_index_bounds_result(object(), index, [index_constraint], 15)

    assert result.status is IndexBoundsCheckStatus.UNSUPPORTED
    assert result.reason == "unsupported_container"
    assert result.issue is None
