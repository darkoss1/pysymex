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

"""Literal-assignment helpers for execution path-feasibility pruning."""

from __future__ import annotations

from collections.abc import Sequence
from typing import cast

import z3

from pysymex.logger import get_logger

logger = get_logger(__name__)
_SIMPLIFY_FAILURES = (z3.Z3Exception, OSError, RuntimeError, ValueError)

__all__ = ["query_simplifies_to_false_after_literal_substitution"]


def query_simplifies_to_false_after_literal_substitution(
    constraints: Sequence[z3.BoolRef],
) -> bool:
    """Return whether path-local literal assignments make the query exactly false."""
    try:
        formula = z3.And(*constraints)
        substitutions = _literal_assignment_substitutions(formula)
        if not substitutions:
            return False
        return z3.is_false(z3.simplify(z3.substitute(formula, *substitutions)))
    except _SIMPLIFY_FAILURES:
        logger.debug(
            "Path feasibility literal-assignment simplification failed; "
            "continuing with solver policy"
        )
        return False


def _literal_assignment_substitutions(
    expression: z3.ExprRef,
) -> tuple[tuple[z3.ExprRef, z3.ExprRef], ...]:
    """Return literal assignments visible in *expression* as Z3 substitutions."""
    substitutions: list[tuple[z3.ExprRef, z3.ExprRef]] = []
    assigned: set[tuple[int, int]] = set()
    seen: set[tuple[int, int]] = set()
    pending: list[z3.ExprRef] = [expression]
    while pending:
        current = pending.pop()
        key = _expr_key(current)
        if key in seen:
            continue
        seen.add(key)
        pair = _literal_assignment_pair(current)
        if pair is not None:
            variable, literal = pair
            variable_key = _expr_key(variable)
            if variable_key not in assigned:
                assigned.add(variable_key)
                substitutions.append((variable, literal))
        pending.extend(current.children())
    return tuple(substitutions)


def _literal_assignment_pair(expression: z3.ExprRef) -> tuple[z3.ExprRef, z3.ExprRef] | None:
    """Return a substitution pair for simple ``var == literal`` or bool assertions."""
    if isinstance(expression, z3.BoolRef):
        if _is_uninterpreted_constant(expression):
            return (expression, z3.BoolVal(True, ctx=_expr_context(expression)))
        if z3.is_not(expression) and expression.num_args() == 1:
            child = expression.arg(0)
            if isinstance(child, z3.BoolRef) and _is_uninterpreted_constant(child):
                return (child, z3.BoolVal(False, ctx=_expr_context(child)))
    if not z3.is_eq(expression) or expression.num_args() != 2:
        return None
    left = expression.arg(0)
    right = expression.arg(1)
    if _is_uninterpreted_constant(left) and _is_literal_value(right):
        return (left, right)
    if _is_uninterpreted_constant(right) and _is_literal_value(left):
        return (right, left)
    return None


def _is_uninterpreted_constant(expression: z3.ExprRef) -> bool:
    """Return whether *expression* is a symbolic variable constant."""
    return z3.is_const(expression) and expression.decl().kind() == z3.Z3_OP_UNINTERPRETED


def _is_literal_value(expression: z3.ExprRef) -> bool:
    """Return whether *expression* is a concrete Z3 literal value."""
    return (
        z3.is_true(expression)
        or z3.is_false(expression)
        or z3.is_int_value(expression)
        or z3.is_rational_value(expression)
        or z3.is_string_value(expression)
        or z3.is_bv_value(expression)
    )


def _expr_key(expression: z3.ExprRef) -> tuple[int, int]:
    """Return a process-local Z3 expression identity key."""
    return (id(expression.ctx_ref()), expression.get_id())


def _expr_context(expression: z3.ExprRef) -> z3.Context:
    """Return the Z3 context across stubs that model ``ctx`` as property or method."""
    context = getattr(expression, "ctx")
    if callable(context):
        return cast("z3.Context", context())
    return cast("z3.Context", context)
