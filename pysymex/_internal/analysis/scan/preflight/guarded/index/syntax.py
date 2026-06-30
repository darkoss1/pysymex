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

"""AST expression parsing for guarded-index preflight diagnostics."""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator


def literal_sequence_length(expression: ast.expr) -> int | None:
    """Return a syntactic sequence length when the expression is exact."""
    if isinstance(expression, ast.List | ast.Tuple):
        return len(expression.elts)
    if isinstance(expression, ast.Constant) and isinstance(expression.value, (str, bytes)):
        return len(expression.value)
    return None


def iter_upper_bounds_from_test(test: ast.AST) -> Iterator[tuple[str, str, int]]:
    """Yield ``index < len(container) - margin`` facts from a branch condition."""
    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And):
        for value in test.values:
            yield from iter_upper_bounds_from_test(value)
        return
    if not isinstance(test, ast.Compare):
        return
    operands = [test.left, *test.comparators]
    for left, op, right in zip(operands, test.ops, operands[1:], strict=False):
        bound = _upper_bound_from_comparison(left, op, right)
        if bound is not None:
            yield bound


def _upper_bound_from_comparison(
    left: ast.expr,
    op: ast.cmpop,
    right: ast.expr,
) -> tuple[str, str, int] | None:
    if not isinstance(op, ast.Lt) or not isinstance(left, ast.Name):
        return None
    len_margin = _len_minus_margin(right)
    if len_margin is None:
        return None
    container_key, margin = len_margin
    return left.id, container_key, margin


def _len_minus_margin(expression: ast.expr) -> tuple[str, int] | None:
    if isinstance(expression, ast.Call):
        container_key = _len_call_container_key(expression)
        if container_key is None:
            return None
        return container_key, 0
    if not isinstance(expression, ast.BinOp):
        return None
    if not isinstance(expression.op, (ast.Sub, ast.Add)):
        return None
    container_key = _len_call_container_key(expression.left)
    if container_key is None:
        return None
    if not isinstance(expression.right, ast.Constant) or not isinstance(
        expression.right.value,
        int,
    ):
        return None
    margin = (
        expression.right.value if isinstance(expression.op, ast.Sub) else -expression.right.value
    )
    return container_key, margin


def _len_call_container_key(expression: ast.expr) -> str | None:
    if not isinstance(expression, ast.Call) or len(expression.args) != 1 or expression.keywords:
        return None
    if not isinstance(expression.func, ast.Name) or expression.func.id != "len":
        return None
    return stable_expr_key(expression.args[0])


def index_name_plus_offset(expression: ast.expr) -> tuple[str, int] | None:
    """Return ``(name, offset)`` for simple ``name +/- constant`` subscripts."""
    if isinstance(expression, ast.Name):
        return expression.id, 0
    if not isinstance(expression, ast.BinOp) or not isinstance(expression.right, ast.Constant):
        return None
    if not isinstance(expression.right.value, int) or not isinstance(expression.left, ast.Name):
        return None
    if isinstance(expression.op, ast.Add):
        return expression.left.id, expression.right.value
    if isinstance(expression.op, ast.Sub):
        return expression.left.id, -expression.right.value
    return None


def stable_expr_key(expression: ast.expr) -> str | None:
    """Return a stable syntactic key for names, constants, and nested subscripts."""
    if isinstance(expression, ast.Name):
        return f"name:{expression.id}"
    if isinstance(expression, ast.Subscript):
        owner = stable_expr_key(expression.value)
        index = stable_expr_key(expression.slice)
        if owner is None or index is None:
            return None
        return f"subscr:{owner}[{index}]"
    if isinstance(expression, ast.Constant):
        return f"const:{expression.value!r}"
    return None
