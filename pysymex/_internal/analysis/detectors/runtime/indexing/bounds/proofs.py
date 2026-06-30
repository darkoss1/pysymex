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

"""Simple Z3 proof helpers for index-error bounds queries."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.constants import Z3_ZERO
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.z3.expression_ops import Z3ExpressionOps

if TYPE_CHECKING:
    from pysymex._internal.core.types.scalars.values import SymbolicValue

_RANGE_PROOF_TIMEOUT_MS = 20


def definitely_in_bounds(
    index: SymbolicValue,
    lower_bound: z3.ArithRef,
    upper_bound: z3.ArithRef,
) -> bool:
    """Return True when concrete index and bounds prove the access in-bounds."""
    if z3.is_false(index.is_int):
        return False
    if not z3.is_true(index.is_int) and not z3.is_true(simplify_expr(index.is_int)):
        return False
    lower = concrete_int_value(lower_bound)
    if lower is None:
        return False
    upper = concrete_int_value(upper_bound)
    if upper is None:
        return False
    concrete_index = symbolic_value_int(index)
    if concrete_index is None:
        proven_range = _concrete_int_range(index.z3_int)
        if proven_range is None and _solver_proves_in_bounds(index.z3_int, lower, upper):
            return True
        if proven_range is None:
            return False
        lower_index, upper_index = proven_range
        return lower <= lower_index and upper_index <= upper
    return lower <= concrete_index < upper


def path_constraints_prove_in_bounds(
    index_expr: z3.ArithRef,
    lower_bound: z3.ArithRef,
    upper_bound: z3.ArithRef,
    path_constraints: list[z3.BoolRef],
) -> bool:
    """Return true when simple active bounds make the OOB disjunction impossible."""
    concrete_index = concrete_int_value(index_expr)
    if concrete_index is not None:
        concrete_upper = _concrete_int_value_from_constraints(upper_bound, path_constraints)
        concrete_lower = _concrete_int_value_from_constraints(lower_bound, path_constraints)
        if (
            concrete_lower is None
            and concrete_upper is not None
            and _is_negative_of(lower_bound, upper_bound)
        ):
            concrete_lower = -concrete_upper
        if concrete_lower is not None and concrete_upper is not None:
            return concrete_lower <= concrete_index < concrete_upper

    if not _has_strict_upper_bound(path_constraints, index_expr, upper_bound):
        return False
    if _has_lower_bound(path_constraints, index_expr, lower_bound):
        return True
    return (
        _is_negative_of(lower_bound, upper_bound)
        and _has_lower_bound(path_constraints, index_expr, ConstraintValues.int(0))
        and _expr_known_nonnegative(upper_bound, path_constraints)
    )


def _concrete_int_value_from_constraints(
    expression: z3.ArithRef,
    constraints: list[z3.BoolRef],
) -> int | None:
    """Return a concrete value for *expression* from equality aliases.

    Length and index facts often arrive through an alias chain rather than a
    direct equality. For example, ``len(xs)`` may be represented as
    ``len_xs_int == xs_len`` and the branch fact as ``32 == len_xs_int``.
    A one-hop scan misses that ``xs_len`` is concretely ``32`` and leaves
    fixed reads such as ``xs[20]`` to the expensive full solver, where
    unrelated bit-vector path facts can turn a local bounds proof into
    ``unknown``.

    Keep this helper deliberately narrow: it only follows arithmetic equality
    aliases and only returns a value when a concrete integer is reached. It
    never treats unsupported formulas as evidence.
    """
    direct = concrete_int_value(expression)
    if direct is not None:
        return direct

    worklist: list[z3.ArithRef] = [expression]
    seen: list[z3.ArithRef] = []
    max_aliases = max(32, len(constraints) * 2)

    while worklist and len(seen) < max_aliases:
        current = worklist.pop()
        if any(Z3ExpressionOps.safe_eq(current, existing) for existing in seen):
            continue
        seen.append(current)

        for constraint in constraints:
            simplified = simplify_expr(constraint)
            if not z3.is_eq(simplified) or simplified.num_args() != 2:
                continue
            left = simplified.arg(0)
            right = simplified.arg(1)
            if not isinstance(left, z3.ArithRef) or not isinstance(right, z3.ArithRef):
                continue

            if Z3ExpressionOps.safe_eq(left, current):
                value = concrete_int_value(right)
                if value is not None:
                    return value
                worklist.append(right)
            elif Z3ExpressionOps.safe_eq(right, current):
                value = concrete_int_value(left)
                if value is not None:
                    return value
                worklist.append(left)
    return None


def symbolic_value_int(value: SymbolicValue) -> int | None:
    """Return a concrete integer payload or simplified integer channel."""
    concrete = value.value
    if isinstance(concrete, int) and not isinstance(concrete, bool):
        return concrete
    if z3.is_int_value(value.z3_int):
        return value.z3_int.as_long()
    simplified_index = simplify_expr(value.z3_int)
    if not z3.is_int_value(simplified_index):
        return None
    return simplified_index.as_long()


def concrete_int_value(expr: z3.ArithRef) -> int | None:
    """Return the concrete integer value of *expr*, if Z3 can simplify it to one."""
    if z3.is_int_value(expr):
        return expr.as_long()
    simplified = simplify_expr(expr)
    if not z3.is_int_value(simplified):
        return None
    return simplified.as_long()


def _concrete_int_range(expr: z3.ArithRef) -> tuple[int, int] | None:
    """Return a half-open concrete range for simple integer expressions."""
    simplified = simplify_expr(expr)
    concrete = concrete_int_value(simplified)
    if concrete is not None:
        return concrete, concrete + 1
    try:
        kind = simplified.decl().kind()
    except z3.Z3Exception:
        return None
    if kind == z3.Z3_OP_MOD and simplified.num_args() == 2:
        divisor = concrete_int_value(cast("z3.ArithRef", simplified.arg(1)))
        if divisor is not None and divisor > 0:
            return 0, divisor
        return None
    if kind == z3.Z3_OP_ADD:
        return _sum_concrete_int_ranges(simplified.children())
    if kind == z3.Z3_OP_SUB and simplified.num_args() == 2:
        left = _concrete_int_range(cast("z3.ArithRef", simplified.arg(0)))
        right = _concrete_int_range(cast("z3.ArithRef", simplified.arg(1)))
        if left is None or right is None:
            return None
        return left[0] - right[1] + 1, left[1] - right[0]
    return None


def _sum_concrete_int_ranges(children: list[z3.ExprRef]) -> tuple[int, int] | None:
    """Return the range sum for child expressions with known concrete ranges."""
    lower = 0
    upper = 0
    for child in children:
        if not isinstance(child, z3.ArithRef):
            return None
        child_range = _concrete_int_range(child)
        if child_range is None:
            return None
        child_lower, child_upper = child_range
        lower += child_lower
        upper += child_upper - 1
    return lower, upper + 1


def _solver_proves_in_bounds(index_expr: z3.ArithRef, lower: int, upper: int) -> bool:
    """Return whether a bounded local solver proves the index expression in-bounds."""
    try:
        solver = z3.Solver()
        solver.set("timeout", _RANGE_PROOF_TIMEOUT_MS)
        solver.add(z3.Or(index_expr < lower, index_expr >= upper))
        return solver.check() == z3.unsat
    except z3.Z3Exception:
        return False


def _has_strict_upper_bound(
    constraints: list[z3.BoolRef],
    index_expr: z3.ArithRef,
    upper_bound: z3.ArithRef,
) -> bool:
    bounds = [upper_bound, *_equality_aliases(upper_bound, constraints)]
    return any(
        _constraint_implies_lt(constraint, index_expr, bound)
        for bound in bounds
        for constraint in constraints
    )


def _has_lower_bound(
    constraints: list[z3.BoolRef],
    index_expr: z3.ArithRef,
    lower_bound: z3.ArithRef,
) -> bool:
    return any(
        _constraint_implies_ge(constraint, index_expr, lower_bound) for constraint in constraints
    )


def _constraint_implies_lt(
    constraint: z3.BoolRef,
    left_expr: z3.ArithRef,
    right_expr: z3.ArithRef,
) -> bool:
    simplified = simplify_expr(constraint)
    if _comparison_matches(simplified, z3.Z3_OP_LT, left_expr, right_expr):
        return True
    if _comparison_matches(simplified, z3.Z3_OP_GT, right_expr, left_expr):
        return True
    if z3.is_not(simplified) and simplified.num_args() == 1:
        child = simplify_expr(simplified.arg(0))
        return _comparison_matches(child, z3.Z3_OP_LE, right_expr, left_expr) or (
            _comparison_matches(child, z3.Z3_OP_GE, left_expr, right_expr)
        )
    return False


def _constraint_implies_ge(
    constraint: z3.BoolRef,
    left_expr: z3.ArithRef,
    right_expr: z3.ArithRef,
) -> bool:
    simplified = simplify_expr(constraint)
    if _comparison_matches(simplified, z3.Z3_OP_GE, left_expr, right_expr):
        return True
    if _comparison_matches(simplified, z3.Z3_OP_LE, right_expr, left_expr):
        return True
    if z3.is_not(simplified) and simplified.num_args() == 1:
        child = simplify_expr(simplified.arg(0))
        return _comparison_matches(child, z3.Z3_OP_LT, left_expr, right_expr) or (
            _comparison_matches(child, z3.Z3_OP_GT, right_expr, left_expr)
        )
    return False


def _comparison_matches(
    expression: z3.ExprRef,
    comparison_kind: int,
    left_expr: z3.ArithRef,
    right_expr: z3.ArithRef,
) -> bool:
    if expression.decl().kind() != comparison_kind or expression.num_args() != 2:
        return False
    return Z3ExpressionOps.safe_eq(expression.arg(0), left_expr) and Z3ExpressionOps.safe_eq(
        expression.arg(1),
        right_expr,
    )


def _is_negative_of(left_expr: z3.ArithRef, right_expr: z3.ArithRef) -> bool:
    simplified = simplify_expr(left_expr + right_expr)
    return z3.eq(simplified, Z3_ZERO)


def _expr_known_nonnegative(
    expression: z3.ArithRef,
    constraints: list[z3.BoolRef],
) -> bool:
    if _expr_is_sequence_length(expression):
        return True
    if _has_lower_bound(constraints, expression, ConstraintValues.int(0)):
        return True
    for alias in _equality_aliases(expression, constraints):
        if _expr_is_sequence_length(alias) or _has_lower_bound(
            constraints,
            alias,
            ConstraintValues.int(0),
        ):
            return True
    return False


def _expr_is_sequence_length(expression: z3.ArithRef) -> bool:
    try:
        return expression.decl().kind() == z3.Z3_OP_SEQ_LENGTH
    except z3.Z3Exception:
        return False


def _equality_aliases(
    expression: z3.ArithRef,
    constraints: list[z3.BoolRef],
) -> list[z3.ArithRef]:
    aliases: list[z3.ArithRef] = []
    for constraint in constraints:
        simplified = simplify_expr(constraint)
        if not z3.is_eq(simplified) or simplified.num_args() != 2:
            continue
        left = simplified.arg(0)
        right = simplified.arg(1)
        if isinstance(left, z3.ArithRef) and Z3ExpressionOps.safe_eq(right, expression):
            aliases.append(left)
        elif isinstance(right, z3.ArithRef) and Z3ExpressionOps.safe_eq(left, expression):
            aliases.append(right)
    return aliases
