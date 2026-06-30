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

"""Exact syntactic literal classification for solver constraints.

This module owns cheap, lossless Boolean classification used before expensive
solver calls. It intentionally does not call ``z3.simplify()`` and only handles
forms whose truth value is visible from literals already present in the AST.
"""

from __future__ import annotations

import z3

from pysymex._internal.core.cache.control import is_process_cache_disabled
from pysymex._internal.core.solver.constraints.exact.literal.cache import (
    MISSING_EXACT_BOOL_LITERAL,
    attached_exact_bool_literal,
    lookup_exact_bool_literal_cache,
    store_exact_bool_literal_cache,
    try_attach_exact_bool_literal,
)

_INTEGER_COMPARISON_KINDS = {
    z3.Z3_OP_EQ,
    z3.Z3_OP_DISTINCT,
    z3.Z3_OP_LT,
    z3.Z3_OP_LE,
    z3.Z3_OP_GT,
    z3.Z3_OP_GE,
}
_MAX_INTERVAL_NODES = 24


def exact_bool_literal(expr: z3.BoolRef) -> bool | None:
    """Return the exact syntactic truth value of *expr*, if locally visible.

    Supported forms are direct Boolean literals, one level of ``Not`` around a
    locally visible literal, locally decidable ``and``/``or`` expressions, and
    integer comparisons over tiny exact intervals such as ``3 < 3`` or
    ``2 + (x % 2) < 4``. Returning ``None`` means the expression is not locally
    decidable; callers must keep using the normal solver path.
    """
    if is_process_cache_disabled():
        return _uncached_exact_bool_literal(expr)

    cached = attached_exact_bool_literal(expr)
    if cached is not MISSING_EXACT_BOOL_LITERAL:
        if cached is None or isinstance(cached, bool):
            return cached
    cache_hit, cached_literal = lookup_exact_bool_literal_cache(expr)
    if cache_hit:
        try_attach_exact_bool_literal(expr, cached_literal)
        return cached_literal

    literal = _uncached_exact_bool_literal(expr)
    try_attach_exact_bool_literal(expr, literal)
    store_exact_bool_literal_cache(expr, literal)
    return literal


def _uncached_exact_bool_literal(expr: z3.BoolRef) -> bool | None:
    """Compute exact literal classification for a cache miss."""
    literal = _direct_exact_bool_literal(expr)
    if literal is not None:
        return literal
    if z3.is_not(expr) and expr.num_args() == 1:
        child = expr.arg(0)
        if not isinstance(child, z3.BoolRef):
            return None
        child_literal = exact_bool_literal(child)
        if child_literal is not None:
            return not child_literal
    return None


def _direct_exact_bool_literal(expr: z3.BoolRef) -> bool | None:
    """Classify direct literal forms without descending through ``Not``."""
    if z3.is_true(expr):
        return True
    if z3.is_false(expr):
        return False
    comparison = _integer_comparison_literal(expr)
    if comparison is not None:
        return comparison
    return _boolean_connective_literal(expr)


def _integer_comparison_literal(expr: z3.BoolRef) -> bool | None:
    """Evaluate comparisons whose operands are all integer literals."""
    kind = expr.decl().kind()
    if kind not in _INTEGER_COMPARISON_KINDS:
        return None

    ranges: list[tuple[int, int]] = []
    for index in range(expr.num_args()):
        arg = expr.arg(index)
        value_range = _integer_interval(arg, _MAX_INTERVAL_NODES)
        if value_range is None:
            return None
        ranges.append(value_range)

    if kind == z3.Z3_OP_EQ:
        if not ranges:
            return None
        if all(interval[0] == interval[1] for interval in ranges):
            values = [interval[0] for interval in ranges]
            return len(set(values)) == 1
        if _ranges_pairwise_disjoint(ranges):
            return False
        return None
    if kind == z3.Z3_OP_DISTINCT:
        if _ranges_pairwise_disjoint(ranges):
            return True
        if all(interval[0] == interval[1] for interval in ranges):
            values = [interval[0] for interval in ranges]
            return len(values) == len(set(values))
        return None
    if len(ranges) != 2:
        return None

    left, right = ranges
    if kind == z3.Z3_OP_LT:
        if left[1] < right[0]:
            return True
        if left[0] >= right[1]:
            return False
    if kind == z3.Z3_OP_LE:
        if left[1] <= right[0]:
            return True
        if left[0] > right[1]:
            return False
    if kind == z3.Z3_OP_GT:
        if left[0] > right[1]:
            return True
        if left[1] <= right[0]:
            return False
    if kind == z3.Z3_OP_GE:
        if left[0] >= right[1]:
            return True
        if left[1] < right[0]:
            return False
    return None


def _boolean_connective_literal(expr: z3.BoolRef) -> bool | None:
    """Classify finite Boolean connectives when children are locally decidable."""
    if z3.is_or(expr):
        saw_unknown = False
        for child in expr.children():
            if not isinstance(child, z3.BoolRef):
                return None
            literal = exact_bool_literal(child)
            if literal is True:
                return True
            if literal is None:
                saw_unknown = True
        return None if saw_unknown else False
    if z3.is_and(expr):
        saw_unknown = False
        for child in expr.children():
            if not isinstance(child, z3.BoolRef):
                return None
            literal = exact_bool_literal(child)
            if literal is False:
                return False
            if literal is None:
                saw_unknown = True
        return None if saw_unknown else True
    return None


def _integer_interval(expr: z3.ExprRef, budget: int) -> tuple[int, int] | None:
    """Return a conservative exact interval for small syntactic integer expressions."""
    if budget <= 0:
        return None
    if z3.is_int_value(expr):
        value = expr.as_long()
        return (value, value)
    if not isinstance(expr, z3.ArithRef):
        return None

    kind = expr.decl().kind()
    if kind == z3.Z3_OP_ADD:
        lower = 0
        upper = 0
        remaining = budget - 1
        for child in expr.children():
            interval = _integer_interval(child, remaining)
            if interval is None:
                return None
            lower += interval[0]
            upper += interval[1]
            remaining -= 1
        return (lower, upper)
    if kind == z3.Z3_OP_SUB:
        if expr.num_args() == 1:
            interval = _integer_interval(expr.arg(0), budget - 1)
            if interval is None:
                return None
            return (-interval[1], -interval[0])
        if expr.num_args() < 2:
            return None
        first = _integer_interval(expr.arg(0), budget - 1)
        if first is None:
            return None
        lower, upper = first
        remaining = budget - 2
        for index in range(1, expr.num_args()):
            interval = _integer_interval(expr.arg(index), remaining)
            if interval is None:
                return None
            lower -= interval[1]
            upper -= interval[0]
            remaining -= 1
        return (lower, upper)
    if kind == z3.Z3_OP_UMINUS and expr.num_args() == 1:
        interval = _integer_interval(expr.arg(0), budget - 1)
        if interval is None:
            return None
        return (-interval[1], -interval[0])
    if kind == z3.Z3_OP_MOD and expr.num_args() == 2:
        divisor = _integer_interval(expr.arg(1), budget - 1)
        if divisor is None or divisor[0] != divisor[1] or divisor[0] <= 0:
            return None
        return (0, divisor[0] - 1)
    return None


def _ranges_pairwise_disjoint(ranges: list[tuple[int, int]]) -> bool:
    """Return whether every interval is disjoint from all prior intervals."""
    sorted_ranges = sorted(ranges)
    for index in range(1, len(sorted_ranges)):
        previous = sorted_ranges[index - 1]
        current = sorted_ranges[index]
        if current[0] <= previous[1]:
            return False
    return True
