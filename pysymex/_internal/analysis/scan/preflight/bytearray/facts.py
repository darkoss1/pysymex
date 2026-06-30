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

"""Static bytearray facts for modulo-index preflight diagnostics."""

from __future__ import annotations

import ast


def bytearray_literal_size(node: ast.AST) -> int | None:
    """Return the concrete size for simple ``bytearray([...])`` constructors."""
    if not isinstance(node, ast.Call):
        return None
    func = node.func
    if not isinstance(func, ast.Name) or func.id != "bytearray" or not node.args:
        return None
    first_arg = node.args[0]
    if isinstance(first_arg, (ast.List, ast.Tuple)):
        return len(first_arg.elts)
    if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, (bytes, bytearray)):
        return len(first_arg.value)
    return None


def modulus_upper_bound(index_expr: ast.AST, assignments: dict[str, ast.AST]) -> int | None:
    """Return the exclusive upper bound for ``expr % constant`` indexes."""
    expr = index_expr
    if isinstance(expr, ast.Name):
        expr = assignments.get(expr.id, expr)
    if not isinstance(expr, ast.BinOp) or not isinstance(expr.op, ast.Mod):
        return None
    if isinstance(expr.right, ast.Constant) and isinstance(expr.right.value, int):
        modulus = expr.right.value
        if modulus > 0:
            return modulus
    return None


def record_assignment_value(
    assignments_stack: list[dict[str, ast.AST]],
    node: ast.Assign,
) -> None:
    """Track simple name assignments in the active function scope."""
    if not assignments_stack:
        return
    for target in node.targets:
        if isinstance(target, ast.Name):
            assignments_stack[-1][target.id] = node.value


def record_bytearray_sizes(
    bytearray_attrs: dict[str, int],
    class_stack: list[str],
    local_sizes_stack: list[dict[str, int]],
    targets: list[ast.expr],
    size: int,
) -> None:
    """Track concrete bytearray sizes for local names and ``self`` attributes."""
    for target in targets:
        if isinstance(target, ast.Name) and local_sizes_stack:
            local_sizes_stack[-1][target.id] = size
        elif (
            isinstance(target, ast.Attribute)
            and isinstance(target.value, ast.Name)
            and target.value.id == "self"
            and class_stack
        ):
            bytearray_attrs[target.attr] = size


def merge_guarded_bounds(
    current_bounds: dict[str, int],
    guarded_bounds: dict[str, int],
) -> dict[str, int]:
    """Merge active upper bounds, keeping the tightest bound per name."""
    merged_bounds = dict(current_bounds)
    for name, upper in guarded_bounds.items():
        old_upper = merged_bounds.get(name)
        merged_bounds[name] = upper if old_upper is None else min(old_upper, upper)
    return merged_bounds


def index_guard_covers_size(
    index_expr: ast.AST,
    index_upper_bounds_stack: list[dict[str, int]],
    size: int,
) -> bool:
    """Return true when a tracked upper-bound guard keeps the index within size."""
    name = _index_name(index_expr)
    if name is None or not index_upper_bounds_stack:
        return False
    guarded_upper = index_upper_bounds_stack[-1].get(name)
    return guarded_upper is not None and guarded_upper <= size


def resolve_container_size(
    node: ast.AST,
    local_sizes_stack: list[dict[str, int]],
    bytearray_attrs: dict[str, int],
) -> int | None:
    """Resolve tracked bytearray size for a local variable or attribute."""
    if isinstance(node, ast.Name) and local_sizes_stack:
        return local_sizes_stack[-1].get(node.id)
    attr_name = _attribute_chain_leaf(node)
    if attr_name is None:
        return None
    return bytearray_attrs.get(attr_name)


def guarded_upper_bounds(test: ast.AST) -> dict[str, int]:
    """Extract simple ``name < int`` upper-bound guards."""
    if not isinstance(test, ast.Compare) or len(test.ops) != 1 or len(test.comparators) != 1:
        return {}
    left = test.left
    right = test.comparators[0]
    if (
        isinstance(left, ast.Name)
        and isinstance(right, ast.Constant)
        and isinstance(right.value, int)
        and isinstance(test.ops[0], ast.Lt)
    ):
        return {left.id: right.value}
    return {}


def _attribute_chain_leaf(node: ast.AST) -> str | None:
    """Return the attribute name from an attribute access node."""
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _index_name(index_expr: ast.AST) -> str | None:
    """Return the variable name from a subscript index expression node."""
    if isinstance(index_expr, ast.Name):
        return index_expr.id
    return None
