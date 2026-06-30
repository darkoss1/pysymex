from __future__ import annotations

import z3

from pysymex._internal.core.constants import Z3_FALSE
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.opcodes.common.compare.exact import (
    exact_concrete_equal,
    exact_equality_condition,
)
from pysymex._internal.execution.opcodes.common.lowering.comparison import ComparisonLowerer


def test_exact_concrete_equal_decides_tuple_with_same_symbolic_int() -> None:
    value, _constraint = SymbolicValue.symbolic_int("value")

    assert exact_concrete_equal(("pause", value), ("pause", value)) is True


def test_exact_equality_condition_negates_same_symbolic_int_tuple() -> None:
    value, _constraint = SymbolicValue.symbolic_int("value")

    condition = exact_equality_condition(("pause", value), ("pause", value), "!=")

    assert condition is not None
    assert z3.is_false(simplify_expr(condition))


def test_exact_concrete_equal_keeps_generic_symbolic_tuple_unknown() -> None:
    value = SymbolicValue(
        _name="maybe_value",
        z3_int=z3.Int("maybe_value_int"),
        is_int=z3.Bool("maybe_value_is_int"),
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
    )

    assert exact_concrete_equal(("pause", value), ("pause", value)) is None


def test_exact_concrete_equal_decides_retained_bytearray_payloads() -> None:
    left = SymbolicList.from_const([ord("b")])
    left.set_runtime_type("bytearray")
    right = SymbolicList.from_const([ord("b")])
    right.set_runtime_type("bytearray")
    other = SymbolicList.from_const([ord("c")])
    other.set_runtime_type("bytearray")

    assert exact_concrete_equal(left, right) is True
    assert exact_concrete_equal(left, b"b") is True
    assert exact_concrete_equal(left, other) is False


def test_comparison_lowerer_preserves_unified_symbolic_bytes_equality() -> None:
    left_bytes = SymbolicBytes.symbolic("left_bytes")
    right_bytes = SymbolicBytes.symbolic("right_bytes")
    left = SymbolicValue.from_specialized(left_bytes)
    right = SymbolicValue.from_specialized(right_bytes)

    result, type_error = ComparisonLowerer(pc=4).lower(left, right, "==")

    assert z3.is_false(simplify_expr(type_error))
    assert z3.is_true(
        simplify_expr(result.z3_bool == (left_bytes.z3_bytes == right_bytes.z3_bytes))
    )


def test_comparison_lowerer_accepts_concrete_bytes_ordering_without_type_error() -> None:
    result, type_error = ComparisonLowerer(pc=5).lower(b"a", b"b", "<")

    assert z3.is_false(simplify_expr(type_error))
    assert z3.is_true(simplify_expr(result.z3_bool))


def test_comparison_lowerer_unrolls_known_length_symbolic_bytes_ordering() -> None:
    left = SymbolicBytes.symbolic("left_order")
    left.z3_len = z3.IntVal(1)

    result, type_error = ComparisonLowerer(pc=6).lower(left, b"\x02", "<")

    solver = z3.Solver()
    solver.add(type_error)
    assert solver.check() == z3.unsat

    solver = z3.Solver()
    solver.add(left.z3_bytes == z3.Unit(z3.BitVecVal(1, 8)))
    solver.add(z3.Not(result.z3_bool))
    assert solver.check() == z3.unsat
