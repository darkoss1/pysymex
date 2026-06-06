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

"""Structural duplicate-removal helpers for solver constraints."""

from __future__ import annotations

import z3

from pysymex.core.z3_utils import safe_z3_eq


def remove_subsumed(constraints: list[z3.BoolRef]) -> list[z3.BoolRef]:
    """Remove structurally duplicate constraints.

    Uses Z3 structural equality to detect and remove exact duplicates.
    Does not perform logical subsumption checking.

    Args:
        constraints: List of Z3 boolean constraints.

    Returns:
        Deduplicated list with structural duplicates removed.
    """
    if len(constraints) <= 1:
        return constraints

    seen: dict[int, list[z3.BoolRef]] = {}
    result: list[z3.BoolRef] = []
    for c in constraints:
        h = c.hash()
        bucket = seen.get(h)
        if bucket is None:
            seen[h] = [c]
            result.append(c)
            continue
        is_dup = False
        for existing in bucket:
            if c is existing or safe_z3_eq(c, existing):
                is_dup = True
                break
        if is_dup:
            continue
        bucket.append(c)
        result.append(c)

    return result
