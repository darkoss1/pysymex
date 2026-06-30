# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Shared Z3 predicates for bounded arithmetic safety checks."""

from __future__ import annotations

from typing import Final

import z3

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE
from pysymex._internal.core.solver.constraints.simplification import simplify_expr

BOUNDED_OVERFLOW_OPERATORS: Final[frozenset[str]] = frozenset(("+", "-", "*", "**", "<<"))


def normalize_assignment_operator(op: str) -> str:
    """Return the base arithmetic operator for assignment-form binary operators."""
    return op.removesuffix("=")


def bounded_integer_overflow_condition(
    left: z3.ArithRef,
    right: z3.ArithRef,
    op: str,
    min_val: int,
    max_val: int,
) -> z3.BoolRef | None:
    """Build the shared bounded-overflow predicate for supported integer operators."""
    normalized_op = normalize_assignment_operator(op)
    if normalized_op == "<<":
        return right > 63
    if normalized_op == "**":
        return z3.And(left > 2, right > 62)
    if normalized_op == "*":
        result = left * right
    elif normalized_op == "+":
        result = left + right
    elif normalized_op == "-":
        result = left - right
    else:
        return None
    return z3.Or(result > max_val, result < min_val)


def divisor_zero_condition(divisor: z3.ExprRef) -> z3.BoolRef:
    """Build the shared predicate that a concrete Z3 divisor can be zero."""
    return divisor == 0


def symbolic_numeric_zero_condition(
    is_int: z3.BoolRef,
    int_expr: z3.ArithRef,
    is_float: z3.BoolRef,
    float_expr: z3.FPRef,
    *,
    include_float: bool,
) -> z3.BoolRef:
    """Build the zero predicate for pysymex's tagged symbolic numeric values."""
    int_zero = z3.And(is_int, divisor_zero_condition(int_expr))
    if not include_float:
        return simplify_expr(int_zero)
    return simplify_expr(z3.Or(int_zero, z3.And(is_float, z3.fpIsZero(float_expr))))


def tagged_numeric_zero_condition(
    *,
    concrete_value: object,
    affinity_type: str,
    is_int: z3.BoolRef,
    int_expr: z3.ArithRef,
    is_bool: z3.BoolRef,
    bool_expr: z3.BoolRef,
    is_float: z3.BoolRef,
    float_expr: z3.FPRef,
    include_float: bool,
) -> z3.BoolRef:
    """Build the zero predicate for a tagged symbolic numeric carrier."""
    if isinstance(concrete_value, (int, float, bool)):
        return Z3_TRUE if concrete_value == 0 else Z3_FALSE
    if affinity_type == "int":
        return divisor_zero_condition(int_expr)
    if affinity_type == "bool":
        return z3.Not(bool_expr)
    if affinity_type == "float":
        return z3.fpIsZero(float_expr) if include_float else Z3_FALSE

    numeric_zero = symbolic_numeric_zero_condition(
        is_int,
        int_expr,
        is_float,
        float_expr,
        include_float=include_float,
    )
    return z3.Or(numeric_zero, z3.And(is_bool, z3.Not(bool_expr)))
