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

"""Lattice operations (join, meet, widen) for abstract value ranges."""

from __future__ import annotations

from typing import Self

from pysymex.analysis.domains.ranges.base import RangeBaseMixin


class RangeLatticeMixin(RangeBaseMixin):
    def union(self: Self, other: Self) -> Self:
        """Compute union (join) of two ranges."""
        if self.is_empty:
            return other
        if other.is_empty:
            return self
        new_low = None if self.low is None or other.low is None else min(self.low, other.low)
        new_high = None if self.high is None or other.high is None else max(self.high, other.high)
        return type(self)(new_low, new_high)

    def intersect(self: Self, other: Self) -> Self:
        """Compute intersection (meet) of two ranges."""
        if self.is_empty or other.is_empty:
            return type(self).empty()
        if self.low is None:
            new_low = other.low
        elif other.low is None:
            new_low = self.low
        else:
            new_low = max(self.low, other.low)
        if self.high is None:
            new_high = other.high
        elif other.high is None:
            new_high = self.high
        else:
            new_high = min(self.high, other.high)
        if new_low is not None and new_high is not None and new_low > new_high:
            return type(self).empty()
        return type(self)(new_low, new_high)

    def widen(self: Self, other: Self) -> Self:
        """Standard widening for loop analysis."""
        if self.is_empty:
            return other
        if other.is_empty:
            return self
        if other.low is not None:
            new_low = None if self.low is None or other.low < self.low else self.low
        else:
            new_low = None
        if other.high is not None:
            new_high = None if self.high is None or other.high > self.high else self.high
        else:
            new_high = None
        return type(self)(new_low, new_high)

    def narrow(self: Self, other: Self) -> Self:
        """Standard narrowing."""
        new_low = self.low if self.low is not None else other.low
        new_high = self.high if self.high is not None else other.high
        return type(self)(new_low, new_high)

    def subset_of(self: Self, other: Self) -> bool:
        """Check if this range is a subset of other."""
        if self.is_empty:
            return True
        if other.is_empty:
            return False
        if other.low is not None:
            if self.low is None or self.low < other.low:
                return False
        if other.high is not None:
            if self.high is None or self.high > other.high:
                return False
        return True


__all__ = ["RangeLatticeMixin"]
