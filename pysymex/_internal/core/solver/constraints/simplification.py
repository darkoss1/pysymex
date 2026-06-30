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

"""Canonical Z3 expression simplification."""

from __future__ import annotations

from typing import Final, overload

import z3

_CANONICAL_SIMPLIFY_KWARGS: Final[dict[str, bool]] = {
    "sort_sums": True,
    "bv_sort_ac": True,
}


@overload
def simplify_expr(expr: z3.BoolRef) -> z3.BoolRef: ...


@overload
def simplify_expr(expr: z3.ArithRef) -> z3.ArithRef: ...


@overload
def simplify_expr(expr: z3.BitVecRef) -> z3.BitVecRef: ...


@overload
def simplify_expr(expr: z3.SeqRef) -> z3.SeqRef: ...


@overload
def simplify_expr(expr: z3.FPRef) -> z3.FPRef: ...


@overload
def simplify_expr(expr: z3.ArrayRef) -> z3.ArrayRef: ...


@overload
def simplify_expr(expr: z3.ReRef) -> z3.ReRef: ...


@overload
def simplify_expr(expr: z3.ExprRef) -> z3.ExprRef: ...


def simplify_expr(expr: z3.ExprRef) -> z3.ExprRef:
    """Simplify one Z3 expression through the constraint simplification SSoT.

    The engine-wide default keeps simplification cheap and canonical by sorting
    arithmetic sums and associative-commutative bit-vector terms. Left-hand-side
    arithmetic normalization stays disabled because it obscures direct aliases
    such as ``x == y`` and can make local simplification bypass solver-owned
    ``UNKNOWN`` outcomes.
    """
    return z3.simplify(expr, **_CANONICAL_SIMPLIFY_KWARGS)
