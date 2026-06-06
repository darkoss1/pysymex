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

"""Predicate queries (is_zero, is_positive, overlaps, etc.) for value ranges."""

from __future__ import annotations

from pysymex.analysis.domains.ranges.base import RangeBaseMixin


class RangePredicatesMixin(RangeBaseMixin):
    def is_full(self) -> bool:
        """Check if this is the full range."""
        return not self.is_empty and self.low is None and self.high is None

    @property
    def is_exact(self) -> bool:
        """Check if this is a singleton."""
        return (
            not self.is_empty
            and self.low is not None
            and self.high is not None
            and self.low == self.high
        )

    @property
    def exact_value(self) -> int | None:
        """Get exact value if singleton."""
        if self.is_exact:
            return self.low
        return None

    def contains(self, value: int) -> bool:
        """Check if value is in range."""
        if self.is_empty:
            return False
        if self.low is not None and value < self.low:
            return False
        if self.high is not None and value > self.high:
            return False
        return True

    def may_be_zero(self) -> bool:
        """Check if range may contain zero."""
        return self.contains(0)

    def must_be_positive(self) -> bool:
        """Check if all values in range are positive."""
        return not self.is_empty and self.low is not None and self.low > 0

    def must_be_negative(self) -> bool:
        """Check if all values in range are negative."""
        return not self.is_empty and self.high is not None and self.high < 0

    def must_be_non_negative(self) -> bool:
        """Check if all values are >= 0."""
        return not self.is_empty and self.low is not None and self.low >= 0

    def must_be_non_positive(self) -> bool:
        """Check if all values are <= 0."""
        return not self.is_empty and self.high is not None and self.high <= 0

    def must_be_non_zero(self) -> bool:
        """Check if zero is definitely not in range."""
        if self.is_empty:
            return True
        return not self.contains(0)


__all__ = ["RangePredicatesMixin"]
