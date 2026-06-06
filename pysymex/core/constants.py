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

"""Shared Z3 literal expressions used by core symbolic-value code.

The constants provide canonical module-level objects for callers that rely on
shared sentinel identity. Keeping them outside ``pysymex.core.solver`` also
avoids pulling solver imports into scalar initialization paths.
"""

from __future__ import annotations

import z3

Z3_TRUE: z3.BoolRef = z3.BoolVal(True)
Z3_FALSE: z3.BoolRef = z3.BoolVal(False)
Z3_INT_SORT: z3.ArithSortRef = z3.IntSort()
Z3_BOOL_SORT: z3.BoolSortRef = z3.BoolSort()
Z3_STRING_SORT: z3.SeqSortRef = z3.StringSort()
Z3_ZERO: z3.ArithRef = z3.IntVal(0)
Z3_ONE: z3.ArithRef = z3.IntVal(1)
Z3_FLOAT_ZERO: z3.FPRef = z3.FPVal(0.0, z3.Float64())
Z3_FLOAT_ONE: z3.FPRef = z3.FPVal(1.0, z3.Float64())
Z3_EMPTY_STRING: z3.SeqRef = z3.StringVal("")

__all__ = [
    "Z3_BOOL_SORT",
    "Z3_EMPTY_STRING",
    "Z3_FALSE",
    "Z3_FLOAT_ONE",
    "Z3_FLOAT_ZERO",
    "Z3_INT_SORT",
    "Z3_ONE",
    "Z3_STRING_SORT",
    "Z3_TRUE",
    "Z3_ZERO",
]
