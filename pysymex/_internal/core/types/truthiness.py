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

"""Core truthiness lowering shared by execution and analysis.

The helper returns the Z3 condition corresponding to a value being truthy.
Execution owns branch stack effects and modeled protocol calls; this module
owns only reusable value-shape facts.
"""

from __future__ import annotations

import z3

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE, Z3_ZERO
from pysymex._internal.core.types.base import SymbolicType
from pysymex._internal.core.types.numeric.float import SymbolicFloat
from pysymex._internal.core.types.scalars.values import SymbolicValue


def _known_int_truthiness(expr: z3.ArithRef) -> z3.BoolRef:
    """Return literal truthiness for fixed integer expressions."""
    if z3.eq(expr, Z3_ZERO):
        return Z3_FALSE
    if z3.is_int_value(expr):
        return Z3_TRUE
    return expr != 0


def _known_string_truthiness(expr: z3.SeqRef) -> z3.BoolRef:
    """Return literal truthiness for fixed string expressions."""
    if z3.is_string_value(expr):
        return Z3_TRUE if expr.as_string() != "" else Z3_FALSE
    return z3.Length(expr) != 0


def _known_fp_truthiness(expr: z3.FPRef) -> z3.BoolRef:
    """Return literal truthiness for fixed FP expressions."""
    if z3.is_fp_value(expr):
        return Z3_FALSE if expr.isZero() else Z3_TRUE
    return z3.Not(z3.fpIsZero(expr))


def get_truthy_expr(value: object) -> z3.BoolRef:
    """Return a Z3 predicate for the value's truthiness under core value facts."""
    if isinstance(value, SymbolicFloat):
        return _known_fp_truthiness(value.z3_expr)

    if isinstance(value, SymbolicValue):
        affinity = value.affinity_type
        if affinity == "bool":
            return value.z3_bool
        if affinity == "int":
            return _known_int_truthiness(value.z3_int)
        if affinity == "float":
            return _known_fp_truthiness(value.z3_float)
        if affinity == "str":
            return _known_string_truthiness(value.z3_str)
        if affinity == "list":
            return _known_int_truthiness(value.z3_int)
        if affinity == "dict":
            return _known_int_truthiness(value.z3_int)
        if affinity == "path":
            return Z3_TRUE
        if affinity == "obj":
            return Z3_TRUE
        if affinity == "none":
            return Z3_FALSE

    if isinstance(value, SymbolicType):
        return value.could_be_truthy()

    if isinstance(value, bool):
        return Z3_TRUE if value else Z3_FALSE
    if isinstance(value, (int, float)):
        return Z3_TRUE if value != 0 else Z3_FALSE
    if value is None:
        return Z3_FALSE

    if isinstance(value, str):
        return Z3_TRUE if value != "" else Z3_FALSE
    if isinstance(value, bytes):
        return Z3_TRUE if value != b"" else Z3_FALSE
    if isinstance(value, list):
        return Z3_TRUE if value != [] else Z3_FALSE
    if isinstance(value, tuple):
        return Z3_TRUE if value != () else Z3_FALSE
    if isinstance(value, dict):
        return Z3_TRUE if value != {} else Z3_FALSE
    if isinstance(value, set):
        return Z3_TRUE if value != set() else Z3_FALSE
    if isinstance(value, frozenset):
        return Z3_TRUE if value != frozenset() else Z3_FALSE
    return Z3_TRUE
