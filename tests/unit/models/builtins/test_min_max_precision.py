"""Precision tests for min()/max() over symbolic integer inputs."""

from __future__ import annotations

import z3

from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins.core.max import MaxModel
from pysymex.models.builtins.core.min import MinModel
from tests.unit.models.builtins.core_model_helpers import state


def test_min_symbolic_list_constrains_result_to_smallest_value() -> None:
    value, value_constraint = SymbolicValue.symbolic_int("value")

    result = MinModel().apply([[value, 1]], {}, state())

    assert isinstance(result.value, SymbolicValue)
    unsat_solver = z3.Solver()
    unsat_solver.add(
        value_constraint,
        *result.constraints,
        result.value.z3_int == 1,
        value.z3_int == 0,
    )
    sat_solver = z3.Solver()
    sat_solver.add(
        value_constraint,
        *result.constraints,
        result.value.z3_int == 1,
        value.z3_int == 2,
    )

    assert unsat_solver.check() == z3.unsat
    assert sat_solver.check() == z3.sat


def test_max_symbolic_list_constrains_result_to_largest_value() -> None:
    value, value_constraint = SymbolicValue.symbolic_int("value")

    result = MaxModel().apply([[value, -1]], {}, state())

    assert isinstance(result.value, SymbolicValue)
    unsat_solver = z3.Solver()
    unsat_solver.add(
        value_constraint,
        *result.constraints,
        result.value.z3_int == -1,
        value.z3_int == 0,
    )
    sat_solver = z3.Solver()
    sat_solver.add(
        value_constraint,
        *result.constraints,
        result.value.z3_int == -1,
        value.z3_int == -2,
    )

    assert unsat_solver.check() == z3.unsat
    assert sat_solver.check() == z3.sat
