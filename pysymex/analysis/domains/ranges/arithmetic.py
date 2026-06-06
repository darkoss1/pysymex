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

"""Arithmetic transfer functions on abstract value ranges."""

from __future__ import annotations

from typing import Self

from pysymex.analysis.domains.ranges.base import RangeBaseMixin


class RangeArithmeticMixin(RangeBaseMixin):
    def add(self: Self, other: Self) -> Self:
        """Range addition."""
        if self.is_empty or other.is_empty:
            return type(self).empty()
        new_low = self.low + other.low if self.low is not None and other.low is not None else None
        new_high = (
            self.high + other.high if self.high is not None and other.high is not None else None
        )
        return type(self)(new_low, new_high)

    def sub(self: Self, other: Self) -> Self:
        """Range subtraction."""
        if self.is_empty or other.is_empty:
            return type(self).empty()
        new_low = self.low - other.high if self.low is not None and other.high is not None else None
        new_high = (
            self.high - other.low if self.high is not None and other.low is not None else None
        )
        return type(self)(new_low, new_high)

    def neg(self: Self) -> Self:
        """Range negation."""
        if self.is_empty:
            return type(self).empty()
        new_low = -self.high if self.high is not None else None
        new_high = -self.low if self.low is not None else None
        return type(self)(new_low, new_high)

    def mul(self: Self, other: Self) -> Self:
        """Range multiplication."""
        if self.is_empty or other.is_empty:
            return type(self).empty()
        if self.is_exact and other.is_exact:
            assert self.low is not None and other.low is not None
            return type(self).exact(self.low * other.low)
        if self.is_full() or other.is_full():
            return type(self).full()
        if (
            self.low is not None
            and self.high is not None
            and other.low is not None
            and other.high is not None
        ):
            products = [
                self.low * other.low,
                self.low * other.high,
                self.high * other.low,
                self.high * other.high,
            ]
            return type(self)(min(products), max(products))
        return type(self).full()

    def div(self: Self, other: Self) -> tuple[Self, bool]:
        """Range division. Returns (result, may_div_by_zero)."""
        if self.is_empty or other.is_empty:
            return type(self).empty(), False
        may_div_by_zero = other.contains(0)
        if other.is_exact and other.low == 0:
            return type(self).empty(), True
        if other.is_exact and other.low is not None and other.low != 0:
            divisor = other.low
            if self.is_exact:
                assert self.low is not None
                return type(self).exact(self.low // divisor), False
            if self.low is not None and self.high is not None:
                results = [self.low // divisor, self.high // divisor]
                return type(self)(min(results), max(results)), False
        return type(self).full(), may_div_by_zero

    def mod(self: Self, other: Self) -> tuple[Self, bool]:
        """Range modulo. Returns (result, may_div_by_zero)."""
        if self.is_empty or other.is_empty:
            return type(self).empty(), False
        may_div_by_zero = other.contains(0)
        if other.is_exact and other.low == 0:
            return type(self).empty(), True
        if other.is_exact and other.low is not None and other.low > 0:
            modulus = other.low
            return type(self)(0, modulus - 1), False
        return type(self).full(), may_div_by_zero


__all__ = ["RangeArithmeticMixin"]
