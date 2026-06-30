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

"""Solver-free symbolic-None guard predicates for execution calls."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

if TYPE_CHECKING:
    from pysymex._internal.core.types.scalars.values import SymbolicValue


def is_uninterpreted_bool_const(expr: z3.BoolRef) -> bool:
    """Return whether *expr* is an uninterpreted Z3 boolean constant."""
    try:
        return z3.is_const(expr) and expr.decl().kind() == z3.Z3_OP_UNINTERPRETED
    except z3.Z3Exception:
        return False


def receiver_non_none_is_static(obj: SymbolicValue) -> bool:
    """Return whether LOAD_ATTR can take the non-None continuation without SMT."""
    if z3.is_false(obj.is_none) or z3.is_true(obj.is_none):
        return True
    return is_uninterpreted_bool_const(obj.is_none)
