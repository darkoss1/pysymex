from __future__ import annotations

import z3

from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.containers.set_retention import (
    replace_exact_set_value,
    set_length_expr,
    set_presence_condition,
)
from pysymex._internal.core.types.scalars.values import SymbolicValue


def test_exact_int_set_presence_constrains_symbolic_needle() -> None:
    source = SymbolicValue.from_const({1, 3})
    needle, needle_constraint = SymbolicValue.symbolic_int("core_set_needle")

    presence = set_presence_condition(source, needle)

    assert presence is not None
    solver = z3.Solver()
    solver.add(needle_constraint, presence, needle.z3_int == 2)
    assert solver.check() == z3.unsat


def test_exact_string_set_presence_constrains_symbolic_needle() -> None:
    source = SymbolicValue.from_const({"a", "bb"})
    needle, needle_constraint = SymbolicValue.symbolic("core_set_string_needle")

    presence = set_presence_condition(source, needle)

    assert presence is not None
    solver = z3.Solver()
    solver.add(
        needle_constraint,
        needle.is_str,
        presence,
        needle.z3_str != ConstraintValues.string("a"),
        needle.z3_str != ConstraintValues.string("bb"),
    )
    assert solver.check() == z3.unsat


def test_replace_exact_set_value_synchronizes_payload_and_length() -> None:
    source = SymbolicValue.from_const({1})

    replace_exact_set_value(source, {1, 2, 3})

    assert source.value == {1, 2, 3}
    length = set_length_expr(source)
    assert length is not None
    assert z3.is_true(z3.simplify(length == 3))
