"""Abstract domain base classes and Interval domain.

Provides the AbstractValue ABC (lattice operations) and the Interval domain.
"""

from __future__ import annotations

import icontract
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import (
    Generic,
    TypeVar,
)

import z3

T = TypeVar("T")


class AbstractValue(ABC, Generic[T]):
    """
    Base class for abstract values.
    Abstract values form a lattice with:
    - join (⊔): least upper bound
    - meet (⊓): greatest lower bound
    - top (⊤): most imprecise
    - bottom (⊥): most precise (empty set)
    """

    @abstractmethod
    def is_top(self) -> bool:
        """Check if this is the top element (unknown)."""

    @abstractmethod
    def is_bottom(self) -> bool:
        """Check if this is the bottom element (empty)."""

    @abstractmethod
    def join(self, other: T) -> T:
        """Compute least upper bound."""

    @abstractmethod
    def meet(self, other: T) -> T:
        """Compute greatest lower bound."""

    @abstractmethod
    def widen(self, other: T) -> T:
        """Widening operator for loop termination."""

    @abstractmethod
    def to_z3_constraint(self, var: z3.ExprRef) -> z3.BoolRef:
        """Convert to Z3 constraint."""

    @classmethod
    @abstractmethod
    def from_concrete(cls, value: object) -> T:
        """Create from concrete value."""

    @classmethod
    @abstractmethod
    def top(cls) -> T:
        """Return top element."""

    @classmethod
    @abstractmethod
    def bottom(cls) -> T:
        """Return bottom element."""


@dataclass
class Interval(AbstractValue["Interval"]):
    """
    Interval abstract domain: x ∈ [lo, hi]
    Represents integers in a range. Supports:
    - [lo, hi]: bounded interval
    - [-∞, hi]: unbounded below
    - [lo, +∞]: unbounded above
    - [-∞, +∞]: top (any integer)
    - ⊥: empty interval (bottom)
    """

    lo: int | None = None
    hi: int | None = None
    _is_bottom: bool = False

    def __post_init__(self):
        """Post init."""
        if (
            self.lo is not None
            and self.hi is not None
            and self.lo > self.hi
            and not self._is_bottom
        ):
            self._is_bottom = True

        if self._is_bottom:
            object.__setattr__(self, "lo", None)
            object.__setattr__(self, "hi", None)

    def is_top(self) -> bool:
        return self.lo is None and self.hi is None and not self._is_bottom

    def is_bottom(self) -> bool:
        return self._is_bottom

    def is_constant(self) -> bool:
        """Check if this is a single value."""
        return self.lo == self.hi and self.lo is not None and not self._is_bottom

    def contains(self, value: int) -> bool:
        """Check if value is in interval."""
        if self._is_bottom:
            return False
        if self.lo is not None and value < self.lo:
            return False
        if self.hi is not None and value > self.hi:
            return False
        return True

    @icontract.ensure(lambda self, other, result: (self.is_bottom() or result.contains(self.lo) if self.lo is not None else True) and (other.is_bottom() or result.contains(other.lo) if other.lo is not None else True))
    def join(self, other: Interval) -> Interval:
        """Least upper bound: [min(lo), max(hi)]"""
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        new_lo = None
        if self.lo is not None and other.lo is not None:
            new_lo = min(self.lo, other.lo)
        new_hi = None
        if self.hi is not None and other.hi is not None:
            new_hi = max(self.hi, other.hi)
        return Interval(new_lo, new_hi)

    @icontract.ensure(lambda self, other, result: result.is_bottom() or (self.contains(result.lo) if result.lo is not None else True))
    def meet(self, other: Interval) -> Interval:
        """Greatest lower bound: [max(lo), min(hi)]"""
        if self.is_bottom() or other.is_bottom():
            return Interval.bottom()
        new_lo = self.lo
        if other.lo is not None:
            if new_lo is None:
                new_lo = other.lo
            else:
                new_lo = max(new_lo, other.lo)
        new_hi = self.hi
        if other.hi is not None:
            if new_hi is None:
                new_hi = other.hi
            else:
                new_hi = min(new_hi, other.hi)
        return Interval(new_lo, new_hi)

    def widen(self, other: Interval) -> Interval:
        """
        Widening: stabilize iteration.
        If new bound extends beyond old, go to infinity.
        """
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        new_lo = self.lo
        if other.lo is None or (self.lo is not None and other.lo < self.lo):
            new_lo = None
        new_hi = self.hi
        if other.hi is None or (self.hi is not None and other.hi > self.hi):
            new_hi = None
        return Interval(new_lo, new_hi)

    def to_z3_constraint(self, var: z3.ExprRef) -> z3.BoolRef:
        """Convert to Z3 constraint."""
        if self.is_bottom():
            return z3.BoolVal(False)
        if self.is_top():
            return z3.BoolVal(True)
        constraints: list[z3.BoolRef] = []
        if self.lo is not None:
            constraints.append(var >= self.lo)
        if self.hi is not None:
            constraints.append(var <= self.hi)
        if not constraints:
            return z3.BoolVal(True)
        return z3.And(*constraints)

    @classmethod
    def from_concrete(cls, value: int) -> Interval:
        """Create singleton interval."""
        return cls(value, value)

    @classmethod
    def top(cls) -> Interval:
        """Return top element."""
        return cls(None, None)

    @classmethod
    def bottom(cls) -> Interval:
        """Return bottom element."""
        return cls(_is_bottom=True)

    @classmethod
    def range(cls, lo: int, hi: int) -> Interval:
        """Create bounded interval."""
        return cls(lo, hi)

    @classmethod
    def at_least(cls, lo: int) -> Interval:
        """Create [lo, +∞)."""
        return cls(lo, None)

    @classmethod
    def at_most(cls, hi: int) -> Interval:
        """Create (-∞, hi]."""
        return cls(None, hi)

    def __add__(self, other: Interval) -> Interval:
        if self.is_bottom() or other.is_bottom():
            return Interval.bottom()
        new_lo = None
        if self.lo is not None and other.lo is not None:
            new_lo = self.lo + other.lo
        new_hi = None
        if self.hi is not None and other.hi is not None:
            new_hi = self.hi + other.hi
        return Interval(new_lo, new_hi)

    def __sub__(self, other: Interval) -> Interval:
        if self.is_bottom() or other.is_bottom():
            return Interval.bottom()
        new_lo = None
        if self.lo is not None and other.hi is not None:
            new_lo = self.lo - other.hi
        new_hi = None
        if self.hi is not None and other.lo is not None:
            new_hi = self.hi - other.lo
        return Interval(new_lo, new_hi)

    def __mul__(self, other: Interval) -> Interval:
        if self.is_bottom() or other.is_bottom():
            return Interval.bottom()
        if self.is_constant() and other.is_constant():
            assert self.lo is not None and other.lo is not None
            result = self.lo * other.lo
            return Interval(result, result)

        endpoints = [self.lo, self.hi, other.lo, other.hi]

        if any(e is None for e in endpoints):

            if self.is_constant() and self.lo == 0:
                return Interval(0, 0)
            if other.is_constant() and other.lo == 0:
                return Interval(0, 0)

            corners: list[int] = []
            unbounded_lo = False
            unbounded_hi = False
            for a, a_is_lo in [(self.lo, True), (self.hi, False)]:
                for b, b_is_lo in [(other.lo, True), (other.hi, False)]:
                    if a is not None and b is not None:
                        corners.append(a * b)
                    elif a is not None and b is None:

                        if a > 0:
                            if not b_is_lo:
                                unbounded_hi = True
                            else:
                                unbounded_lo = True
                        elif a < 0:
                            if not b_is_lo:
                                unbounded_lo = True
                            else:
                                unbounded_hi = True

                    elif a is None and b is not None:
                        if b > 0:
                            if not a_is_lo:
                                unbounded_hi = True
                            else:
                                unbounded_lo = True
                        elif b < 0:
                            if not a_is_lo:
                                unbounded_lo = True
                            else:
                                unbounded_hi = True
                    else:

                        unbounded_lo = True
                        unbounded_hi = True
            result_lo: int | None = None
            result_hi: int | None = None
            if corners:
                result_lo = None if unbounded_lo else min(corners)
                result_hi = None if unbounded_hi else max(corners)
            else:
                result_lo = None
                result_hi = None
            return Interval(result_lo, result_hi)

        corners = []
        for a in [self.lo, self.hi]:
            for b in [other.lo, other.hi]:
                if a is not None and b is not None:
                    corners.append(a * b)
        if not corners:
            return Interval.top()
        return Interval(min(corners), max(corners))

    def __neg__(self) -> Interval:
        if self.is_bottom():
            return Interval.bottom()
        new_lo = None if self.hi is None else -self.hi
        new_hi = None if self.lo is None else -self.lo
        return Interval(new_lo, new_hi)

    def __repr__(self) -> str:
        """Repr."""
        if self.is_bottom():
            return "⊥"
        lo_str = str(self.lo) if self.lo is not None else "-∞"
        hi_str = str(self.hi) if self.hi is not None else "+∞"
        return f"[{lo_str }, {hi_str }]"
