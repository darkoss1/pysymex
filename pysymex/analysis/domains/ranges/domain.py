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

"""Value range domain model (interval, unbounded, empty)."""

from __future__ import annotations

from dataclasses import dataclass

from pysymex.analysis.domains.ranges.arithmetic import RangeArithmeticMixin
from pysymex.analysis.domains.ranges.lattice import RangeLatticeMixin
from pysymex.analysis.domains.ranges.predicates import RangePredicatesMixin


@dataclass(frozen=True)
class Range(RangeArithmeticMixin, RangeLatticeMixin, RangePredicatesMixin):
    """Represents a range of integer values [low, high]."""

    low: int | None = None
    high: int | None = None
    is_empty: bool = False
    is_numeric: bool = False

    @classmethod
    def empty(cls) -> Range:
        """Create empty range (bottom)."""
        return cls(is_empty=True)

    @classmethod
    def full(cls) -> Range:
        """Create full range (top)."""
        return cls(None, None)

    @classmethod
    def exact(cls, value: int) -> Range:
        """Create singleton range."""
        return cls(value, value, is_numeric=True)

    @classmethod
    def at_least(cls, min_val: int) -> Range:
        """Create range [min_val, +infinity)."""
        return cls(min_val, None)

    @classmethod
    def at_most(cls, max_val: int) -> Range:
        """Create range (-infinity, max_val]."""
        return cls(None, max_val)

    @classmethod
    def between(cls, low: int, high: int) -> Range:
        """Create range [low, high]."""
        if low > high:
            return cls.empty()
        return cls(low, high)

    def __str__(self) -> str:
        """Return a human-readable string representation."""
        if self.is_empty:
            return "∅"
        low_str = str(self.low) if self.low is not None else "-∞"
        high_str = str(self.high) if self.high is not None else "+∞"
        return f"[{low_str}, {high_str}]"


__all__ = ["Range"]
