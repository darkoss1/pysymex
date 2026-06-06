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

"""Z3 expression traversal helpers for logical detectors."""

from __future__ import annotations

from collections.abc import Iterable

import z3

from pysymex.analysis.detectors.logical.utils.expr import extract_symbol_name


def get_variables(expr: z3.ExprRef, *, include_internal: bool = False) -> set[z3.ExprRef]:
    """Recursively extract all uninterpreted constants (variables) from an expression."""
    vars_set: set[z3.ExprRef] = set()
    worklist = [expr]
    seen = {expr.get_id()}

    ignore_patterns = ["_is_", "cmp_mixed", "type_constraint", "iter_"]

    while worklist:
        node = worklist.pop()

        if z3.is_const(node) and node.decl().arity() == 0:
            if node.decl().kind() == z3.Z3_OP_UNINTERPRETED:
                name = node.decl().name()
                if include_internal or not any(pat in name for pat in ignore_patterns):
                    vars_set.add(node)
                continue

        for child in node.children():
            cid = child.get_id()
            if cid not in seen:
                seen.add(cid)
                worklist.append(child)

    return vars_set


def get_variables_for_core(
    core: Iterable[z3.ExprRef], *, include_internal: bool = False
) -> set[z3.ExprRef]:
    """Extract all variables from an unsat core."""
    vars_set: set[z3.ExprRef] = set()
    for c in core:
        vars_set.update(get_variables(c, include_internal=include_internal))
    return vars_set


def count_variables(core: Iterable[z3.ExprRef]) -> int:
    """Return the number of unique variables in the unsat core."""
    return len(get_variables_for_core(core))


def iter_subexpressions(expr: z3.ExprRef) -> Iterable[z3.ExprRef]:
    """Yield expression nodes in depth-first order."""
    worklist = [expr]
    seen = {expr.get_id()}
    while worklist:
        node = worklist.pop()
        yield node
        for child in node.children():
            cid = child.get_id()
            if cid not in seen:
                seen.add(cid)
                worklist.append(child)


def get_variable_names(core: Iterable[z3.ExprRef]) -> set[str]:
    """Get the string names of all variables in the core."""
    return {v.decl().name() for v in get_variables_for_core(core)}


def get_variable_names_all(core: Iterable[z3.ExprRef]) -> set[str]:
    """Get variable names including internal/type marker variables."""
    return {str(v.decl().name()) for v in get_variables_for_core(core, include_internal=True)}


def expr_contains_variable(expr: z3.ExprRef, variable_name: str) -> bool:
    """Check whether an expression contains a specific symbolic variable."""
    for node in iter_subexpressions(expr):
        name = extract_symbol_name(node)
        if name == variable_name:
            return True
    return False


def extract_constants(expr: z3.ExprRef) -> list[int]:
    """Extract all integer constants from an expression."""
    consts: list[int] = []
    worklist: list[z3.ExprRef] = [expr]
    while worklist:
        node = worklist.pop()
        if z3.is_int_value(node):
            consts.append(node.as_long())
        for child in node.children():
            worklist.append(child)
    return consts


__all__ = [
    "count_variables",
    "expr_contains_variable",
    "extract_constants",
    "get_variable_names",
    "get_variable_names_all",
    "get_variables",
    "get_variables_for_core",
    "iter_subexpressions",
]
