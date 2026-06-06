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

"""Abstract state mapping variables to value ranges."""

from __future__ import annotations

from dataclasses import dataclass, field

from pysymex.analysis.domains.ranges.domain import Range


@dataclass
class RangeState:
    """State for range analysis."""

    variables: dict[str, Range] = field(default_factory=dict[str, Range])
    stack: list[Range] = field(default_factory=list[Range])
    is_bottom: bool = False

    @classmethod
    def bottom(cls) -> RangeState:
        return cls(is_bottom=True)

    @classmethod
    def top(cls) -> RangeState:
        return cls()

    def copy(self) -> RangeState:
        """Copy."""
        if self.is_bottom:
            return RangeState.bottom()
        return RangeState(variables=dict(self.variables), stack=list(self.stack))

    def get(self, var: object) -> Range:
        return self.variables.get(str(var), Range.full())

    def set(self, var: object, range_val: Range) -> None:
        self.variables[str(var)] = range_val

    def push(self, range_val: Range) -> None:
        self.stack.append(range_val)

    def pop(self) -> Range:
        """Pop."""
        if self.stack:
            return self.stack.pop()
        return Range.full()

    def peek(self, depth: int = 0) -> Range:
        """Peek."""
        idx = -(depth + 1)
        if abs(idx) <= len(self.stack):
            return self.stack[idx]
        return Range.full()

    def join(self, other: RangeState) -> RangeState:
        """Join."""
        if self.is_bottom:
            return other.copy()
        if other.is_bottom:
            return self.copy()
        result = RangeState()
        all_vars = set(self.variables.keys()) | set(other.variables.keys())
        for var in all_vars:
            result.variables[var] = self.get(var).union(other.get(var))
        return result

    def widen(self, other: RangeState) -> RangeState:
        """Widen."""
        if self.is_bottom:
            return other.copy()
        if other.is_bottom:
            return self.copy()
        result = RangeState()
        all_vars = set(self.variables.keys()) | set(other.variables.keys())
        for var in all_vars:
            result.variables[var] = self.get(var).widen(other.get(var))
        return result

    def subset_of(self, other: RangeState) -> bool:
        """Check if self is a subset of other."""
        if self.is_bottom:
            return True
        if other.is_bottom:
            return False
        for var, range_val in self.variables.items():
            if not range_val.subset_of(other.get(var)):
                return False
        for var in other.variables:
            if var not in self.variables and not Range.full().subset_of(other.get(var)):
                return False
        return True


__all__ = ["RangeState"]
