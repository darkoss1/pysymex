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

"""Operator inspection and real-relaxation helpers for logical detectors."""

from __future__ import annotations

from collections.abc import Iterable

import z3

from pysymex.core.solver.constraints.hashing import get_real_val
from pysymex.core.solver.engine.queries import check_sat_result
from pysymex.core.solver.engine.results import SolverResult
from pysymex.logger import get_logger

logger = get_logger(__name__)
_REAL_RELAXATION_FAILURES = (
    z3.Z3Exception,
    OSError,
    RuntimeError,
    ValueError,
    TypeError,
    AttributeError,
    IndexError,
)


def has_operator(expr: z3.ExprRef, target_kinds: set[int]) -> bool:
    """Check if the expression uses any of the specified Z3 operator kinds."""
    worklist = [expr]
    seen = {expr.get_id()}

    while worklist:
        node = worklist.pop()
        if z3.is_app(node):
            if node.decl().kind() in target_kinds:
                return True
        for child in node.children():
            cid = child.get_id()
            if cid not in seen:
                seen.add(cid)
                worklist.append(child)
    return False


def core_has_operator(core: Iterable[z3.ExprRef], target_kinds: set[int]) -> bool:
    """Check if the core uses any of the specified Z3 operator kinds."""
    for c in core:
        if has_operator(c, target_kinds):
            return True
    return False


def count_operator(expr: z3.ExprRef, target_kinds: set[int]) -> int:
    """Count how many times specific operators appear in the expression."""
    count = 0
    worklist = [expr]
    seen = {expr.get_id()}

    while worklist:
        node = worklist.pop()
        if z3.is_app(node):
            if node.decl().kind() in target_kinds:
                count += 1
        for child in node.children():
            cid = child.get_id()
            if cid not in seen:
                seen.add(cid)
                worklist.append(child)
    return count


def core_count_operator(core: Iterable[z3.ExprRef], target_kinds: set[int]) -> int:
    """Count occurrences of operators across the core."""
    return sum(count_operator(c, target_kinds) for c in core)


def relax_to_real(expr: z3.ExprRef, var_map: dict[z3.ExprRef, z3.ExprRef]) -> z3.ExprRef:
    """Translate an integer expression to a real expression."""
    if z3.is_const(expr) and expr.decl().arity() == 0:
        if expr.decl().kind() == z3.Z3_OP_UNINTERPRETED:
            if expr.sort() == z3.IntSort():
                if expr not in var_map:
                    var_map[expr] = z3.Real(expr.decl().name())
                return var_map[expr]
            return expr
        elif expr.sort() == z3.IntSort():
            return get_real_val(expr.as_long())
        return expr

    if z3.is_app(expr):
        decl = expr.decl()
        children = [relax_to_real(c, var_map) for c in expr.children()]

        kind = decl.kind()
        if kind == z3.Z3_OP_ADD:
            return z3.Sum(*children)
        if kind == z3.Z3_OP_MUL:
            return z3.Product(*children)
        if kind == z3.Z3_OP_SUB:
            return children[0] - children[1] if len(children) == 2 else -children[0]
        if kind == z3.Z3_OP_DIV or kind == z3.Z3_OP_IDIV:
            return children[0] / children[1]
        if kind == z3.Z3_OP_EQ:
            return children[0] == children[1]
        if kind == z3.Z3_OP_DISTINCT:
            return children[0] != children[1]
        if kind == z3.Z3_OP_LT:
            return children[0] < children[1]
        if kind == z3.Z3_OP_LE:
            return children[0] <= children[1]
        if kind == z3.Z3_OP_GT:
            return children[0] > children[1]
        if kind == z3.Z3_OP_GE:
            return children[0] >= children[1]
        if kind == z3.Z3_OP_AND:
            return z3.And(*children)
        if kind == z3.Z3_OP_OR:
            return z3.Or(*children)
        if kind == z3.Z3_OP_NOT:
            return z3.Not(children[0])
        if kind == z3.Z3_OP_IMPLIES:
            return z3.Implies(children[0], children[1])
        if kind == z3.Z3_OP_ITE:
            return z3.If(children[0], children[1], children[2])

        return expr

    return expr


def check_sat_over_reals_result(core: list[z3.BoolRef]) -> SolverResult:
    """Check real-relaxed constraints without collapsing solver uncertainty.

    Returns:
        SAT when the relaxed Boolean constraints are satisfiable, UNSAT when
        they are contradictory, and UNKNOWN when relaxation or solver checking
        is inconclusive.
    """
    var_map: dict[z3.ExprRef, z3.ExprRef] = {}
    relaxed_constraints: list[z3.BoolRef] = []
    for c in core:
        try:
            rc = relax_to_real(c, var_map)
            if isinstance(rc, z3.BoolRef):
                relaxed_constraints.append(rc)
            else:
                return SolverResult.unknown()
        except _REAL_RELAXATION_FAILURES:
            logger.debug(
                "Logical detector real relaxation failed; treating result as UNKNOWN",
                exc_info=True,
            )
            return SolverResult.unknown()
    return check_sat_result(relaxed_constraints)


def is_sat_over_reals(core: list[z3.BoolRef]) -> bool:
    """Return whether the core is definitely SAT when integers are relaxed to reals.

    Notes:
        ``False`` includes UNSAT, UNKNOWN, and relaxation failure. Use
        :func:`check_sat_over_reals_result` when the caller needs to
        distinguish inconclusive evidence.
    """
    return check_sat_over_reals_result(core).is_sat


__all__ = [
    "check_sat_over_reals_result",
    "core_count_operator",
    "core_has_operator",
    "count_operator",
    "has_operator",
    "is_sat_over_reals",
    "relax_to_real",
]
