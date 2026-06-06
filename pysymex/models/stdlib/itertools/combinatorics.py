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

"""Combinatoric itertools model functions."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

if TYPE_CHECKING:
    from pysymex.core.types.containers.lists import SymbolicList
else:
    from pysymex.core.types.containers.lists import SymbolicList


def model_product(*iterables: SymbolicList, repeat: int = 1) -> SymbolicList:
    """Model itertools.product(*iterables, repeat=1)."""
    result = SymbolicList.empty("product_result")
    if iterables:
        product_len = iterables[0].z3_len
        for it in iterables[1:]:
            product_len = product_len * it.z3_len
        for _ in range(repeat - 1):
            product_len = product_len * iterables[0].z3_len
            for it in iterables[1:]:
                product_len = product_len * it.z3_len
        result.z3_len = product_len

    return result


def model_permutations(
    iterable: SymbolicList,
    r: int | None = None,
) -> SymbolicList:
    """Model itertools.permutations(iterable, r=None)."""
    result = SymbolicList.empty("permutations_result")
    return result


def model_combinations(
    iterable: SymbolicList,
    r: int,
) -> SymbolicList:
    """Model itertools.combinations(iterable, r)."""
    result = SymbolicList.empty("combinations_result")
    return result


def model_combinations_with_replacement(
    iterable: SymbolicList,
    r: int,
) -> SymbolicList:
    """Model itertools.combinations_with_replacement(iterable, r)."""
    return SymbolicList.empty("combinations_wr_result")


def model_zip_longest(
    *iterables: SymbolicList,
    _fillvalue: object = None,
) -> SymbolicList:
    """Model itertools.zip_longest(*iterables, fillvalue=None)."""
    result = SymbolicList.empty("zip_longest_result")
    if iterables:
        max_len: z3.ArithRef | z3.ExprRef = iterables[0].z3_len
        for it in iterables[1:]:
            max_len = z3.If(it.z3_len > max_len, it.z3_len, max_len)
        result.z3_len = max_len

    return result
