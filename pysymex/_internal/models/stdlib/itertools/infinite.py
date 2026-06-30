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

"""Infinite/repeating itertools models."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.solver.constraints.values import ConstraintValues

if TYPE_CHECKING:
    from pysymex._internal.core.types.containers.lists import SymbolicList
else:
    from pysymex._internal.core.types.containers.lists import SymbolicList


def model_count(start: int = 0, step: int = 1) -> object:
    """Model itertools.count(start=0, step=1).

    Returns an infinite iterator counting from start.
    """
    from pysymex._internal.core.types.scalars.values import SymbolicValue

    result, _ = SymbolicValue.symbolic("count")
    return result


def model_cycle(iterable: SymbolicList) -> SymbolicList:
    """Model itertools.cycle(iterable).

    Returns infinite iterator cycling through iterable.
    """
    return SymbolicList.empty("cycle_result")


def model_repeat(obj: object, times: int | None = None) -> SymbolicList:
    """Model itertools.repeat(obj, times=None).

    Returns iterator repeating obj.
    If times is None, repeats indefinitely.

    Args:
        obj: Object to repeat
        times: Number of times (None = infinite)

    Returns:
        A SymbolicList

    """
    result = SymbolicList.empty("repeat_result")
    if times is not None:
        result.z3_len = ConstraintValues.int(times)
    return result
