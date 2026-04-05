# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""Structural constraint hashing for pysymex.

Provides content-addressable hashing for Z3 constraints using native
AST-based hashing instead of expensive string conversion.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import z3


def structural_hash(constraints: list[z3.BoolRef] | list[z3.ExprRef]) -> int:
    """Compute a structural hash of Z3 constraints using native AST hashing.

    Uses Z3's built-in __hash__ combined with tuple-style hashing to avoid
    XOR cancellation issues (where A ^ A = 0).

    Args:
        constraints: List of Z3 boolean constraints.

    Returns:
        Integer hash suitable for use as a cache key.
    """

    h = 0x3456789A
    mult = 1000000007
    for c in constraints:
        ch = c.hash() & 0xFFFFFFFFFFFFFFFF
        h = ((h ^ ch) * mult) & 0xFFFFFFFFFFFFFFFF
        mult = (mult + 82520) & 0xFFFFFFFFFFFFFFFF
    h ^= len(constraints)
    return h & 0xFFFFFFFFFFFFFFFF


def structural_hash_sorted(constraints: list[z3.BoolRef] | list[z3.ExprRef]) -> int:
    """Compute an order-independent structural hash of Z3 constraints.

    Sorts constraint hashes before combining so that the same set of
    constraints in any order produces the same hash.

    Args:
        constraints: List of Z3 boolean constraints.

    Returns:
        Integer hash independent of constraint ordering.
    """
    if not constraints:
        return 0
    hashes = sorted(c.hash() for c in constraints)

    h = 0x3456789A
    mult = 1000000007
    for ch in hashes:
        ch = ch & 0xFFFFFFFFFFFFFFFF
        h = ((h ^ ch) * mult) & 0xFFFFFFFFFFFFFFFF
        mult = (mult + 82520) & 0xFFFFFFFFFFFFFFFF
    h ^= len(constraints)
    return h & 0xFFFFFFFFFFFFFFFF
