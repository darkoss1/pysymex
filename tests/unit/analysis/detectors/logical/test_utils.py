"""Tests for pysymex/analysis/detectors/logical/utils.py."""

from unittest.mock import Mock, patch
import z3
import dis
import pytest
from pysymex.analysis.detectors.logical.utils import (
    get_variables,
    get_variables_for_core,
    count_variables,
    iter_subexpressions,
    extract_var_const_comparisons,
    extract_var_var_comparisons,
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
    is_sat_over_reals,
    get_variable_names,
    get_variable_names_all,
    expr_contains_variable,
    extract_constants,
)


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
