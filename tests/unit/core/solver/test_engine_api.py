"""Tests for top-level solver engine APIs."""

from __future__ import annotations

import time

import pytest
import z3

from pysymex.core.solver.engine.constraints import (
    as_bool_constraint,
    normalize_constraint_iterable,
)
from pysymex.core.solver.engine.context import active_incremental_solver
from pysymex.core.solver.engine.incremental import IncrementalSolver
from pysymex.core.solver.engine.policies import path_may_be_feasible
from pysymex.core.solver.engine.queries import (
    DEFAULT_SOLVER_TIMEOUT_MS,
    check_sat_result,
    clear_solver_caches,
    create_solver,
    get_model,
    get_model_cached,
    get_model_cached_result,
    get_model_result,
    get_model_string,
    prove,
    prove_result,
)
from pysymex.core.solver.engine.results import SolverResult


class _ConvertibleConstraint:
    def __init__(self, expr: z3.ExprRef) -> None:
        self._expr = expr

    def to_z3(self) -> z3.ExprRef:
        return self._expr


def test_safe_z3_eq_context_soundness() -> None:
    """Check that safe_z3_eq correctly handles cross-context and recycled Z3 AST IDs."""
    from pysymex.core.types.base import safe_z3_eq

    ctx1 = z3.Context()
    ctx2 = z3.Context()
    x1 = z3.Int("x", ctx1) > 0
    x2 = z3.Int("y", ctx2) > 0

    assert safe_z3_eq(x1, x2) is False
    assert safe_z3_eq(x1, x1) is True


def test_create_solver() -> None:
    solver = create_solver()
    assert isinstance(solver, z3.Solver)


def test_path_may_be_feasible() -> None:
    x = z3.Int("x")
    assert path_may_be_feasible([x == 1])


def test_check_sat_result_preserves_structured_status() -> None:
    x = z3.Int("structured_sat_x")

    sat_result = check_sat_result([x == 1])
    unsat_result = check_sat_result([x == 1, x == 2])

    assert (sat_result.is_sat, sat_result.is_unsat, sat_result.is_unknown) == (
        True,
        False,
        False,
    )
    assert (unsat_result.is_sat, unsat_result.is_unsat, unsat_result.is_unknown) == (
        False,
        True,
        False,
    )


def test_check_sat_result_reports_malformed_constraint_as_unknown() -> None:
    x = z3.Int("malformed_top_level_sat_x")

    result = check_sat_result([x == 1, object()])

    assert (result.is_sat, result.is_unsat, result.is_unknown) == (False, False, True)


def test_as_bool_constraint_accepts_convertible_boolref() -> None:
    constraint = z3.Bool("convertible_constraint")
    normalized = as_bool_constraint(_ConvertibleConstraint(constraint))

    assert normalized is constraint


def test_normalize_constraint_iterable_drops_non_bool_convertible_expr() -> None:
    constraint = z3.Bool("kept_convertible_constraint")
    non_bool = z3.Int("dropped_convertible_expr")

    normalized = normalize_constraint_iterable(
        [_ConvertibleConstraint(constraint), _ConvertibleConstraint(non_bool)]
    )

    assert len(normalized) == 1
    assert normalized[0] is constraint


def test_check_sat_result_uses_active_incremental_solver() -> None:
    x = z3.Int("active_top_level_sat_x")
    solver = IncrementalSolver()
    token = active_incremental_solver.set(solver)
    try:
        result = check_sat_result([x == 9])
    finally:
        active_incremental_solver.reset(token)

    assert result.is_sat is True
    assert solver.get_stats()["queries"] == 1


def test_check_sat_result_preserves_active_solver_deadline_unknown() -> None:
    x = z3.Int("deadline_top_level_sat_x")
    solver = IncrementalSolver(timeout_ms=1000)
    solver.set_deadline(time.perf_counter() - 1.0)
    token = active_incremental_solver.set(solver)
    try:
        result = check_sat_result([x == 1])
    finally:
        active_incremental_solver.reset(token)

    assert (result.is_sat, result.is_unsat, result.is_unknown) == (False, False, True)


def test_get_model() -> None:
    x = z3.Int("x")
    assert get_model([x == 1]) is not None


def test_get_model_result_preserves_structured_status() -> None:
    x = z3.Int("structured_model_x")

    sat_result = get_model_result([x == 1])
    unsat_result = get_model_result([x == 1, x == 2])
    malformed_result = get_model_result([x == 1, object()])

    assert (sat_result.is_sat, sat_result.is_unsat, sat_result.is_unknown) == (
        True,
        False,
        False,
    )
    assert sat_result.model is not None
    assert (unsat_result.is_sat, unsat_result.is_unsat, unsat_result.is_unknown) == (
        False,
        True,
        False,
    )
    assert unsat_result.model is None
    assert (malformed_result.is_sat, malformed_result.is_unsat, malformed_result.is_unknown) == (
        False,
        False,
        True,
    )


def test_get_model_returns_none_for_malformed_constraint() -> None:
    x = z3.Int("malformed_model_x")
    assert get_model([x == 1, object()]) is None


def test_get_model_cached_result_preserves_malformed_constraint_unknown() -> None:
    x = z3.Int("malformed_cached_model_result_x")

    result = get_model_cached_result([x == 1, object()])

    assert (result.is_sat, result.is_unsat, result.is_unknown) == (False, False, True)
    assert result.model is None


def test_get_model_uses_active_incremental_solver() -> None:
    x = z3.Int("active_model_x")
    solver = IncrementalSolver()
    token = active_incremental_solver.set(solver)
    try:
        model = get_model([x == 7])
    finally:
        active_incremental_solver.reset(token)

    assert model is not None
    assert solver.get_stats()["queries"] == 1


def test_get_model_result_uses_active_incremental_solver() -> None:
    x = z3.Int("active_model_result_x")
    solver = IncrementalSolver()
    token = active_incremental_solver.set(solver)
    try:
        result = get_model_result([x == 7])
    finally:
        active_incremental_solver.reset(token)

    assert result.is_sat is True
    assert result.model is not None
    assert solver.get_stats()["queries"] == 1


def test_get_model_result_preserves_active_solver_unsat() -> None:
    x = z3.Int("active_unsat_model_result_x")
    solver = IncrementalSolver()
    token = active_incremental_solver.set(solver)
    try:
        result = get_model_result([x == 1, x == 2])
    finally:
        active_incremental_solver.reset(token)

    assert (result.is_sat, result.is_unsat, result.is_unknown) == (False, True, False)
    assert result.model is None


def test_get_model_result_preserves_active_solver_deadline_unknown() -> None:
    x = z3.Int("deadline_model_result_x")
    solver = IncrementalSolver(timeout_ms=1000)
    solver.set_deadline(time.perf_counter() - 1.0)
    token = active_incremental_solver.set(solver)
    try:
        result = get_model_result([x == 1])
    finally:
        active_incremental_solver.reset(token)

    assert (result.is_sat, result.is_unsat, result.is_unknown) == (False, False, True)
    assert result.model is None
    assert solver.get_stats()["queries"] == 1


def test_get_model_result_uses_active_structured_model_query(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    x = z3.Int("active_structured_model_query_x")
    solver = IncrementalSolver()
    calls = 0

    def fake_check_sat_cached(constraints: list[z3.BoolRef]) -> SolverResult:
        nonlocal calls
        calls += 1
        assert len(constraints) == 1
        assert z3.eq(constraints[0], x == 1)
        return SolverResult.unknown()

    def fail_check_sat_result(
        constraints: list[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> SolverResult:
        _ = constraints, known_sat_prefix_len
        raise AssertionError("active get_model_result should use check_sat_cached directly")

    monkeypatch.setattr(solver, "check_sat_cached", fake_check_sat_cached)
    monkeypatch.setattr(solver, "check_sat_result", fail_check_sat_result)
    token = active_incremental_solver.set(solver)
    try:
        result = get_model_result([x == 1])
    finally:
        active_incremental_solver.reset(token)

    assert result.is_unknown
    assert calls == 1


def test_get_model_string() -> None:
    x = z3.Int("x")
    assert get_model_string([x == 1]) is not None


def test_get_model_cached_returns_none_for_malformed_constraint() -> None:
    x = z3.Int("malformed_cached_model_x")
    assert get_model_cached([x == 1, object()]) is None


def test_prove() -> None:
    x = z3.Int("x")
    assert prove(x == x)


def test_prove_returns_false_for_refutable_claim() -> None:
    x = z3.Int("refutable_prove_x")

    assert prove(x > 0) is False


def test_prove_result_preserves_structured_status() -> None:
    x = z3.Int("structured_prove_x")

    proved = prove_result(x == x)
    refuted = prove_result(x > 0)
    malformed = prove_result(object())

    assert (proved.is_sat, proved.is_unsat, proved.is_unknown) == (False, True, False)
    assert (refuted.is_sat, refuted.is_unsat, refuted.is_unknown) == (True, False, False)
    assert refuted.model is not None
    assert (malformed.is_sat, malformed.is_unsat, malformed.is_unknown) == (False, False, True)


def test_prove_result_uses_standalone_solver() -> None:
    x = z3.Int("standalone_prove_x")
    solver = IncrementalSolver()
    solver.add(x > 1)
    token = active_incremental_solver.set(solver)
    try:
        result = prove_result(x > 0)
    finally:
        active_incremental_solver.reset(token)

    assert result.is_sat is True


def test_clear_solver_caches() -> None:
    clear_solver_caches()
    assert isinstance(DEFAULT_SOLVER_TIMEOUT_MS, int)
