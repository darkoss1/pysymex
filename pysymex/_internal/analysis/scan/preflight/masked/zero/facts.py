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

"""Flow facts for masked zero-division preflight diagnostics."""

from __future__ import annotations

import ast


def expr_mentions_name(node: ast.AST, name: str) -> bool:
    """Return true when an AST expression references a variable name."""
    return any(isinstance(child, ast.Name) and child.id == name for child in ast.walk(node))


def apply_assignment_masks(
    node: ast.Assign,
    masked_vars_stack: list[set[str]],
    zero_guard_stack: list[set[str]],
) -> None:
    """Update tracked masked and zero-guarded names for one assignment."""
    if not masked_vars_stack:
        return
    masked_assignment = _is_masked_assignment(node.value)
    for target in node.targets:
        if not isinstance(target, ast.Name):
            continue
        if masked_assignment:
            masked_vars_stack[-1].add(target.id)
        else:
            masked_vars_stack[-1].discard(target.id)
            if zero_guard_stack:
                zero_guard_stack[-1].discard(target.id)


def zero_guard_names(test: ast.AST, masked_vars_stack: list[set[str]]) -> set[str]:
    """Identify masked variables guarded equal to zero in a comparison."""
    if not masked_vars_stack or not isinstance(test, ast.Compare):
        return set()
    if len(test.ops) != 1 or len(test.comparators) != 1 or not isinstance(test.ops[0], ast.Eq):
        return set()
    left = test.left
    right = test.comparators[0]
    if isinstance(left, ast.Name) and isinstance(right, ast.Constant) and right.value == 0:
        return {left.id} & masked_vars_stack[-1]
    if isinstance(right, ast.Name) and isinstance(left, ast.Constant) and left.value == 0:
        return {right.id} & masked_vars_stack[-1]
    return set()


def guarded_divisor_name(node: ast.BinOp, zero_guard_stack: list[set[str]]) -> str | None:
    """Return the guarded-zero name used by a division divisor, if any."""
    if not isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)):
        return None
    for name in zero_guard_stack[-1] if zero_guard_stack else ():
        if expr_mentions_name(node.right, name):
            return name
    return None


def _is_masked_assignment(value: ast.expr) -> bool:
    """Return whether an expression creates a non-negative bit-mask value."""
    return (
        isinstance(value, ast.BinOp)
        and isinstance(value.op, ast.BitAnd)
        and isinstance(value.right, ast.Constant)
        and isinstance(value.right.value, int)
        and value.right.value >= 0
    )
