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

"""Shared helpers for symbolic container models."""

from __future__ import annotations

import z3

from pysymex.core.constants import Z3_FALSE, Z3_TRUE
from pysymex.core.types.scalars.values import fresh_name


def known_length_truthiness(length: z3.ArithRef, *, truthy: bool) -> z3.BoolRef:
    """Return literal truthiness for concrete lengths, otherwise the exact predicate."""
    if z3.is_int_value(length):
        is_nonempty = length.as_long() > 0
        if truthy:
            return Z3_TRUE if is_nonempty else Z3_FALSE
        return Z3_FALSE if is_nonempty else Z3_TRUE
    if truthy:
        return length > 0
    return length == 0


def storage_int_expr(expr: object, name_prefix: str) -> z3.ArithRef:
    """Return an integer expression or a fresh unconstrained storage placeholder.

    Limitations:
        Non-integer payloads are not converted or constrained to the returned
        placeholder in this helper.
    """
    if isinstance(expr, z3.ArithRef) and z3.is_int(expr):
        return expr
    return z3.Int(fresh_name(name_prefix))
