from __future__ import annotations

from collections.abc import Iterable

import z3

from pysymex._internal.core.solver.feasibility_context import bind_path_feasibility_oracle
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.dict.selection import (
    NO_DEFAULT,
    conditional_retained_lookup_value,
)
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue


def _z3_path_may_be_feasible(
    constraints: Iterable[z3.BoolRef],
    *,
    known_sat_prefix_len: int | None = None,
) -> bool:
    solver = z3.Solver()
    solver.add(*constraints)
    return solver.check() == z3.sat


def test_conditional_retained_lookup_proves_present_int_relationship() -> None:
    y, y_constraint = SymbolicValue.symbolic_int("core_dict_key_y")
    key = SymbolicValue(
        _name="core_dict_key",
        z3_int=z3.If(y.z3_int == 0, z3.IntVal(0), z3.IntVal(1)),
        is_int=z3.BoolVal(True),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
        is_str=z3.BoolVal(False),
        is_none=z3.BoolVal(False),
        affinity_type="int",
    )
    source = SymbolicDict.from_const({0: 2, 1: 1})
    state = VMState(path_constraints=[y_constraint])

    with bind_path_feasibility_oracle(_z3_path_may_be_feasible):
        result = conditional_retained_lookup_value(
            source,
            key,
            NO_DEFAULT,
            state=state,
            name="core_dict_lookup",
        )

    assert isinstance(result, SymbolicValue)
    solver = z3.Solver()
    solver.add(y_constraint, result.z3_int == 0)
    assert solver.check() == z3.unsat


def test_conditional_retained_lookup_preserves_string_default_branch() -> None:
    y, y_constraint = SymbolicValue.symbolic_int("core_dict_string_key_y")
    key = SymbolicValue(
        _name="core_dict_string_key",
        z3_int=y.z3_int % 3,
        is_int=z3.BoolVal(True),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
        is_str=z3.BoolVal(False),
        is_none=z3.BoolVal(False),
        affinity_type="int",
    )
    source = SymbolicDict.from_const({0: "a", 1: "bb"})

    result = conditional_retained_lookup_value(
        source,
        key,
        "",
        state=VMState(path_constraints=[y_constraint]),
        name="core_dict_string_lookup",
    )

    assert isinstance(result, SymbolicString)
    solver = z3.Solver()
    solver.add(y_constraint, y.z3_int % 3 == 2, result.z3_len != 0)
    assert solver.check() == z3.unsat
