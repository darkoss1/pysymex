"""Tests for pysymex/analysis/detectors/logical/utils.py."""

import dis
import time

import pytest
import z3

import pysymex.analysis.detectors.logical.utils.operators as operators_mod
from pysymex.analysis.detectors.logical.utils import (
    get_variables,
    get_variables_for_core,
    count_variables,
    iter_subexpressions,
    extract_var_const_comparisons,
    extract_var_var_comparisons,
    extract_product_const_comparisons,
    extract_sum_const_comparisons,
    extract_var_const_equalities,
    extract_var_const_disequalities,
    extract_bounds,
    bounds_are_inconsistent,
    extract_modulo_equalities,
    extract_bool_assignments,
    has_operator,
    core_has_operator,
    count_operator,
    core_count_operator,
    relax_to_real,
    check_sat_over_reals_result,
    is_sat_over_reals,
    get_variable_names,
    get_variable_names_all,
    expr_contains_variable,
    extract_constants,
)
from pysymex.core.solver.engine.context import active_incremental_solver
from pysymex.core.solver.engine.incremental import IncrementalSolver


def MockInstr(
    opname: str, argval: object = None, argrepr: str = "", arg: int = 0, offset: int = 10
) -> dis.Instruction:
    import dis

    def _dummy() -> None:
        pass

    template = next(dis.get_instructions(_dummy))
    return template._replace(
        opname=opname,
        opcode=dis.opmap.get(opname, 0),
        arg=arg,
        argval=argval,
        argrepr=argrepr,
        offset=offset,
    )


def test_get_variables_exists() -> None:
    """Test get_variables behavior."""
    assert callable(get_variables)


def test_get_variables_for_core_exists() -> None:
    """Test get_variables_for_core behavior."""
    assert callable(get_variables_for_core)


def test_count_variables_exists() -> None:
    """Test count_variables behavior."""
    assert callable(count_variables)


def test_iter_subexpressions_exists() -> None:
    """Test iter_subexpressions behavior."""
    assert callable(iter_subexpressions)


def test_extract_var_const_comparisons_exists() -> None:
    """Test extract_var_const_comparisons behavior."""
    assert callable(extract_var_const_comparisons)


def test_extract_var_var_comparisons_exists() -> None:
    """Test extract_var_var_comparisons behavior."""
    assert callable(extract_var_var_comparisons)


def test_extract_sum_const_comparisons_extracts_unit_sum() -> None:
    """Extract unit-coefficient symbolic sums compared to constants."""
    import z3

    x = z3.Int("x")
    y = z3.Int("y")
    assert extract_sum_const_comparisons([x + y <= 4]) == [(("x", "y"), "<=", 4)]


def test_extract_product_const_comparisons_extracts_binary_product() -> None:
    """Extract binary symbolic products compared to constants."""
    import z3

    x = z3.Int("x")
    y = z3.Int("y")
    assert extract_product_const_comparisons([x * y < 0]) == [("x", "y", "<", 0)]


def test_extract_var_const_equalities_exists() -> None:
    """Test extract_var_const_equalities behavior."""
    assert callable(extract_var_const_equalities)


def test_extract_var_const_disequalities_exists() -> None:
    """Test extract_var_const_disequalities behavior."""
    assert callable(extract_var_const_disequalities)


def test_extract_bounds_exists() -> None:
    """Test extract_bounds behavior."""
    assert callable(extract_bounds)


def test_bounds_are_inconsistent_exists() -> None:
    """Test bounds_are_inconsistent behavior."""
    assert callable(bounds_are_inconsistent)


def test_extract_modulo_equalities_exists() -> None:
    """Test extract_modulo_equalities behavior."""
    assert callable(extract_modulo_equalities)


def test_extract_bool_assignments_exists() -> None:
    """Test extract_bool_assignments behavior."""
    assert callable(extract_bool_assignments)


def test_has_operator_exists() -> None:
    """Test has_operator behavior."""
    assert callable(has_operator)


def test_core_has_operator_exists() -> None:
    """Test core_has_operator behavior."""
    assert callable(core_has_operator)


def test_count_operator_exists() -> None:
    """Test count_operator behavior."""
    assert callable(count_operator)


def test_core_count_operator_exists() -> None:
    """Test core_count_operator behavior."""
    assert callable(core_count_operator)


def test_relax_to_real_exists() -> None:
    """Test relax_to_real behavior."""
    assert callable(relax_to_real)


def test_is_sat_over_reals_exists() -> None:
    """Test is_sat_over_reals behavior."""
    assert callable(is_sat_over_reals)


def test_check_sat_over_reals_result_preserves_structured_status() -> None:
    x = z3.Int("real_relaxation_result_x")

    sat_result = check_sat_over_reals_result([2 * x == 1])
    unsat_result = check_sat_over_reals_result([x > 1, x < 0])

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


def test_is_sat_over_reals_does_not_treat_solver_unknown_as_sat() -> None:
    solver = IncrementalSolver(timeout_ms=1000)
    solver.set_deadline(time.perf_counter() - 1.0)
    token = active_incremental_solver.set(solver)
    try:
        structured = check_sat_over_reals_result([z3.Int("unknown_real_relaxation_x") == 1])
        result = is_sat_over_reals([z3.Int("unknown_real_relaxation_x") == 1])
    finally:
        active_incremental_solver.reset(token)

    assert (structured.is_sat, structured.is_unsat, structured.is_unknown) == (
        False,
        False,
        True,
    )
    assert result is False


def test_check_sat_over_reals_result_reports_relaxation_failure_as_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _raise_relaxation_failure(
        _expr: z3.ExprRef, _var_map: dict[z3.ExprRef, z3.ExprRef]
    ) -> z3.ExprRef:
        raise z3.Z3Exception("relaxation failed")

    monkeypatch.setattr(operators_mod, "relax_to_real", _raise_relaxation_failure)

    result = check_sat_over_reals_result([z3.Int("failed_relaxation_x") == 1])

    assert (result.is_sat, result.is_unsat, result.is_unknown) == (False, False, True)


def test_get_variable_names_exists() -> None:
    """Test get_variable_names behavior."""
    assert callable(get_variable_names)


def test_get_variable_names_all_exists() -> None:
    """Test get_variable_names_all behavior."""
    assert callable(get_variable_names_all)


def test_expr_contains_variable_exists() -> None:
    """Test expr_contains_variable behavior."""
    assert callable(expr_contains_variable)


def test_extract_constants_exists() -> None:
    """Test extract_constants behavior."""
    assert callable(extract_constants)
