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

"""Shared Z3 expression parsing helpers for logical detectors."""

from __future__ import annotations

import z3


def unwrap_numeric(expr: z3.ExprRef) -> z3.ExprRef:
    """Strip common wrappers used by solver normalization."""
    node = expr
    while z3.is_app(node) and node.decl().kind() == z3.Z3_OP_TO_REAL and node.num_args() == 1:
        node = node.arg(0)
    return node


def as_int_value(expr: z3.ExprRef) -> int | None:
    """Convert a Z3 expression to an integer value if possible.

    Args:
        expr (z3.ExprRef): The Z3 expression to convert.

    Returns:
        int | None: The integer value if the expression is a numeric constant, otherwise None.
    """
    node = unwrap_numeric(expr)
    try:
        if z3.is_int_value(node):
            return node.as_long()
    except Exception:
        return None
    return None


def as_bool_value(expr: z3.ExprRef) -> bool | None:
    """Convert a Z3 expression to a boolean value if possible.

    Args:
        expr (z3.ExprRef): The Z3 expression to convert.

    Returns:
        bool | None: True if the expression is Z3 true, False if Z3 false, otherwise None.
    """
    if z3.is_true(expr):
        return True
    if z3.is_false(expr):
        return False
    return None


def extract_symbol_name(expr: z3.ExprRef) -> str | None:
    """Extract the name of a Z3 symbolic constant.

    Args:
        expr (z3.ExprRef): The Z3 expression containing the symbol.

    Returns:
        str | None: The string name of the symbol if it is a constant, otherwise None.
    """
    node = unwrap_numeric(expr)
    if (
        z3.is_const(node)
        and node.decl().arity() == 0
        and node.decl().kind() == z3.Z3_OP_UNINTERPRETED
    ):
        return str(node.decl().name())
    return None


def invert_comparison(op: str) -> str:
    """Invert a comparison operator string.

    Args:
        op (str): The comparison operator (e.g., '>', '<=').

    Returns:
        str: The inverted comparison operator (e.g., '<', '>=').
    """
    return {
        ">": "<",
        ">=": "<=",
        "<": ">",
        "<=": ">=",
        "==": "==",
        "!=": "!=",
    }.get(op, op)


def _negate_comparison(op: str) -> str:
    """Negate a comparison operator string.

    Args:
        op (str): The comparison operator to negate.

    Returns:
        str: The negated comparison operator (e.g., '<=' for '>').
    """
    return {
        ">": "<=",
        ">=": "<",
        "<": ">=",
        "<=": ">",
        "==": "!=",
        "!=": "==",
    }.get(op, op)


def parse_cmp(expr: z3.ExprRef) -> tuple[str, z3.ExprRef, z3.ExprRef] | None:
    """Parse a Z3 comparison expression into its operator and operands.

    Args:
        expr (z3.ExprRef): The Z3 expression to parse.

    Returns:
        tuple[str, z3.ExprRef, z3.ExprRef] | None: A tuple containing the operator string,
        the left-hand operand, and the right-hand operand, or None if the expression
        is not a supported comparison.
    """
    if z3.is_not(expr) and expr.num_args() == 1:
        inner = parse_cmp(expr.arg(0))
        if inner is None:
            return None
        op, lhs, rhs = inner
        return (_negate_comparison(op), lhs, rhs)

    if not z3.is_app(expr):
        return None

    kind = expr.decl().kind()
    op = {
        z3.Z3_OP_GT: ">",
        z3.Z3_OP_GE: ">=",
        z3.Z3_OP_LT: "<",
        z3.Z3_OP_LE: "<=",
        z3.Z3_OP_EQ: "==",
        z3.Z3_OP_DISTINCT: "!=",
    }.get(kind)
    if op is None or expr.num_args() != 2:
        return None
    return (op, expr.arg(0), expr.arg(1))


__all__ = [
    "as_bool_value",
    "as_int_value",
    "extract_symbol_name",
    "invert_comparison",
    "parse_cmp",
    "unwrap_numeric",
]
