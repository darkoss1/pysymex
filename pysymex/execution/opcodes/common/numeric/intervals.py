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

"""Extract simple integer bounds from path constraints for exact numeric lowering.

Used by :mod:`pysymex.execution.opcodes.common.numeric.ops` when exponent or shift
amounts are symbolic: ``extract_interval`` walks linear comparisons on one Z3
integer symbol, then ``piecewise_exact_*`` encodes small non-negative ranges
(``0..MAX_EXACT_SYMBOLIC_EXPONENT``) without widening to full havoc.

Limitations:
    Only single-symbol ``==``, ``<``, ``<=``, ``>``, ``>=`` (and negated forms)
    are recognized; compound or multi-variable constraints yield unbounded intervals.
"""

from __future__ import annotations

from dataclasses import dataclass

import z3

from pysymex.core.solver.constraints.hashing import get_int_val
from pysymex.core.types.scalars.values import py_floor_div

MAX_EXACT_SYMBOLIC_EXPONENT = 8


@dataclass(frozen=True, slots=True)
class IntInterval:
    """Represents discovered integer bounds for a symbolic expression."""

    lower: int | None = None
    upper: int | None = None

    def contains_non_negative_small_range(self) -> bool:
        """Return whether the interval is fully bounded inside ``0..8``."""
        if self.lower is None or self.upper is None:
            return False
        return 0 <= self.lower <= self.upper <= MAX_EXACT_SYMBOLIC_EXPONENT


def extract_interval(constraints: list[z3.BoolRef], symbol: z3.ArithRef) -> IntInterval:
    """Extract simple integer bounds for *symbol* from the current path.

    Returns open bounds (``None`` lower/upper) when no matching linear facts exist.
    Does not call the solver; only inspects syntactic constraint shape.
    """
    interval = IntInterval()
    lower = interval.lower
    upper = interval.upper

    for constraint in constraints:
        normalized = normalize_constraint(constraint)
        if normalized is None:
            continue
        relation, value = normalized
        if not matches_symbol(relation[0], symbol):
            continue
        operator_name = relation[1]
        if operator_name == "==":
            lower = value if lower is None else max(lower, value)
            upper = value if upper is None else min(upper, value)
        elif operator_name == ">=":
            lower = value if lower is None else max(lower, value)
        elif operator_name == ">":
            lower = (value + 1) if lower is None else max(lower, value + 1)
        elif operator_name == "<=":
            upper = value if upper is None else min(upper, value)
        elif operator_name == "<":
            upper = (value - 1) if upper is None else min(upper, value - 1)

    return IntInterval(lower=lower, upper=upper)


def normalize_constraint(
    constraint: z3.BoolRef,
) -> tuple[tuple[z3.ExprRef, str], int] | None:
    """Normalize simple constraints to ``(symbol, operator, constant)`` form."""
    target = constraint
    negated = False
    if target.decl().kind() == z3.Z3_OP_NOT and target.num_args() == 1:
        target = target.arg(0)
        negated = True

    if target.num_args() != 2:
        return None

    left = target.arg(0)
    right = target.arg(1)
    left_constant = extract_int_constant(left)
    right_constant = extract_int_constant(right)

    kind = target.decl().kind()
    if left_constant is None and right_constant is None:
        return None

    if left_constant is not None and right_constant is None:
        relation = relation_from_kind(kind, negated, swapped=True)
        if relation is None:
            return None
        return ((right, relation), left_constant)

    if right_constant is not None and left_constant is None:
        relation = relation_from_kind(kind, negated, swapped=False)
        if relation is None:
            return None
        return ((left, relation), right_constant)

    return None


def relation_from_kind(kind: int, negated: bool, swapped: bool) -> str | None:
    """Map a Z3 comparator kind to a normalized operator string."""
    direct: dict[int, str] = {
        z3.Z3_OP_EQ: "==",
        z3.Z3_OP_GE: ">=",
        z3.Z3_OP_GT: ">",
        z3.Z3_OP_LE: "<=",
        z3.Z3_OP_LT: "<",
    }
    inverse: dict[str, str] = {
        "==": "!=",
        ">=": "<",
        ">": "<=",
        "<=": ">",
        "<": ">=",
    }
    swapped_map: dict[str, str] = {
        ">=": "<=",
        ">": "<",
        "<=": ">=",
        "<": ">",
        "==": "==",
    }
    relation = direct.get(kind)
    if relation is None:
        return None
    if swapped:
        relation = swapped_map[relation]
    if negated:
        relation = inverse.get(relation)
    return relation if relation in {"==", ">=", ">", "<=", "<"} else None


def matches_symbol(candidate: z3.ExprRef, symbol: z3.ArithRef) -> bool:
    """Return whether *candidate* and *symbol* refer to the same Z3 AST."""
    return z3.eq(candidate, symbol)


def extract_int_constant(expr: z3.ExprRef) -> int | None:
    """Extract a Python integer from a Z3 integer numeral expression."""
    if isinstance(expr, z3.IntNumRef):
        return expr.as_long()
    return None


def piecewise_exact_power(
    base: z3.ArithRef,
    exponent: z3.ArithRef,
    lower: int,
    upper: int,
) -> z3.ArithRef:
    """Encode exact bounded exponentiation over a small non-negative range."""
    values = list(range(lower, upper + 1))
    tail = exact_power_expr(base, values[-1])
    for value in reversed(values[:-1]):
        tail = z3.If(exponent == get_int_val(value), exact_power_expr(base, value), tail)
    return tail


def piecewise_exact_shift_left(
    value: z3.ArithRef,
    shift: z3.ArithRef,
    lower: int,
    upper: int,
) -> z3.ArithRef:
    """Encode exact left shift over a small non-negative shift interval."""
    values = list(range(lower, upper + 1))
    tail = value * get_int_val(1 << values[-1])
    for current in reversed(values[:-1]):
        tail = z3.If(shift == get_int_val(current), value * get_int_val(1 << current), tail)
    return tail


def piecewise_exact_shift_right(
    value: z3.ArithRef,
    shift: z3.ArithRef,
    lower: int,
    upper: int,
) -> z3.ArithRef:
    """Encode exact right shift over a small non-negative shift interval."""
    values = list(range(lower, upper + 1))
    tail = py_floor_div(value, get_int_val(1 << values[-1]))
    for current in reversed(values[:-1]):
        tail = z3.If(
            shift == get_int_val(current),
            py_floor_div(value, get_int_val(1 << current)),
            tail,
        )
    return tail


def exact_power_expr(base: z3.ArithRef, exponent: int) -> z3.ArithRef:
    """Build repeated-multiplication power expressions for small exponents."""
    result = get_int_val(1)
    for _ in range(exponent):
        result = result * base
    return result
