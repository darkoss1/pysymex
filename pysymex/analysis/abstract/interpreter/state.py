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

"""Composite abstract domain, abstract state, and warning types.

Provides:
- NumericProduct: reduced product of Interval, SignValue, and Congruence
- AbstractState: maps variables to abstract values with stack operations
- AbstractWarning, DivisionByZeroWarning, IndexOutOfBoundsWarning
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pysymex.analysis.abstract.interpreter.values import (
    AbstractValue,
    Congruence,
    Interval,
    Sign,
    SignValue,
)


@dataclass
class NumericProduct(AbstractValue):
    """
    Reduced product of interval and sign domains.
    Combines multiple domains for better precision.
    """

    interval: Interval
    sign: SignValue
    congruence: Congruence = field(default_factory=Congruence.top)

    @classmethod
    def bottom(cls) -> NumericProduct:
        return cls(Interval.bottom(), SignValue.bottom(), Congruence.bottom())

    @classmethod
    def top(cls) -> NumericProduct:
        return cls(Interval.top(), SignValue.top(), Congruence.top())

    @classmethod
    def const(cls, value: int) -> NumericProduct:
        return cls(
            Interval.const(value),
            SignValue.from_const(value),
            Congruence.const(value),
        )

    def reduce(self) -> NumericProduct:
        """Apply reduction to improve precision."""
        if self.interval.is_bottom() or self.sign.is_bottom() or self.congruence.is_bottom():
            return NumericProduct.bottom()
        new_interval = self.interval
        if self.sign.must_be_positive():
            new_interval = new_interval.meet(Interval.positive())
        elif self.sign.must_be_negative():
            new_interval = new_interval.meet(Interval.range(None, -1))
        elif self.sign.sign == Sign.ZERO:
            new_interval = new_interval.meet(Interval.const(0))
        new_sign = self.sign
        if new_interval.must_be_positive():
            new_sign = SignValue(Sign.POSITIVE)
        elif new_interval.must_be_negative():
            new_sign = SignValue(Sign.NEGATIVE)
        elif new_interval.is_const() and new_interval.get_const() == 0:
            new_sign = SignValue(Sign.ZERO)
        return NumericProduct(new_interval, new_sign, self.congruence)

    def is_bottom(self) -> bool:
        return self.interval.is_bottom() or self.sign.is_bottom() or self.congruence.is_bottom()

    def is_top(self) -> bool:
        return self.interval.is_top() and self.sign.is_top() and self.congruence.is_top()

    def may_be_zero(self) -> bool:
        """Check if zero is a possible value."""
        return (
            self.interval.may_be_zero()
            and self.sign.may_be_zero()
            and self.congruence.may_be_zero()
        )

    def must_be_non_zero(self) -> bool:
        """Check if zero is definitely not possible."""
        return self.interval.must_be_non_zero() or self.sign.must_be_non_zero()

    def join(self, other: AbstractValue) -> NumericProduct:
        """Join."""
        if not isinstance(other, NumericProduct):
            return NumericProduct.top()
        return NumericProduct(
            self.interval.join(other.interval),
            self.sign.join(other.sign),
            self.congruence.join(other.congruence),
        ).reduce()

    def meet(self, other: AbstractValue) -> NumericProduct:
        """Meet."""
        if not isinstance(other, NumericProduct):
            return self
        return NumericProduct(
            self.interval.meet(other.interval),
            self.sign.meet(other.sign),
            self.congruence.meet(other.congruence),
        ).reduce()

    def widen(self, other: AbstractValue) -> NumericProduct:
        """Widen."""
        if not isinstance(other, NumericProduct):
            return NumericProduct.top()
        return NumericProduct(
            self.interval.widen(other.interval),
            self.sign.widen(other.sign),
            self.congruence.widen(other.congruence),
        )

    def narrow(self, other: AbstractValue) -> NumericProduct:
        """Narrow."""
        if not isinstance(other, NumericProduct):
            return self
        return NumericProduct(
            self.interval.narrow(other.interval),
            self.sign.narrow(other.sign),
            self.congruence.narrow(other.congruence),
        ).reduce()

    def leq(self, other: AbstractValue) -> bool:
        """Leq."""
        if not isinstance(other, NumericProduct):
            return False
        return (
            self.interval.leq(other.interval)
            and self.sign.leq(other.sign)
            and self.congruence.leq(other.congruence)
        )

    def add(self, other: NumericProduct) -> NumericProduct:
        return NumericProduct(
            self.interval.add(other.interval),
            self.sign.add(other.sign),
            Congruence.top(),
        ).reduce()

    def sub(self, other: NumericProduct) -> NumericProduct:
        return NumericProduct(
            self.interval.sub(other.interval),
            self.sign.sub(other.sign),
            Congruence.top(),
        ).reduce()

    def mul(self, other: NumericProduct) -> NumericProduct:
        return NumericProduct(
            self.interval.mul(other.interval),
            self.sign.mul(other.sign),
            Congruence.top(),
        ).reduce()

    def div(self, other: NumericProduct) -> tuple[NumericProduct, bool]:
        """Division with division-by-zero check."""
        interval_result, int_may_raise = self.interval.div(other.interval)
        sign_result, sign_may_raise = self.sign.div(other.sign)
        may_raise = int_may_raise or sign_may_raise or other.may_be_zero()
        return (
            NumericProduct(
                interval_result,
                sign_result,
                Congruence.top(),
            ).reduce(),
            may_raise,
        )

    def mod(self, other: NumericProduct) -> tuple[NumericProduct, bool]:
        """Modulo with division-by-zero check."""
        interval_result, int_may_raise = self.interval.mod(other.interval)
        sign_result, sign_may_raise = self.sign.mod(other.sign)
        may_raise = int_may_raise or sign_may_raise or other.may_be_zero()
        return (
            NumericProduct(
                interval_result,
                sign_result,
                Congruence.top(),
            ).reduce(),
            may_raise,
        )


@dataclass
class AbstractState:
    """
    Abstract state mapping variables to abstract values.
    """

    variables: dict[str, NumericProduct] = field(default_factory=dict[str, NumericProduct])
    stack: list[NumericProduct] = field(default_factory=list[NumericProduct])
    collection_sizes: dict[str, NumericProduct] = field(default_factory=dict[str, NumericProduct])
    _is_bottom: bool = False

    @classmethod
    def bottom(cls) -> AbstractState:
        return cls(_is_bottom=True)

    @classmethod
    def top(cls) -> AbstractState:
        return cls()

    def copy(self) -> AbstractState:
        """Copy."""
        if self._is_bottom:
            return AbstractState.bottom()
        return AbstractState(
            variables=dict(self.variables),
            stack=list(self.stack),
            collection_sizes=dict(self.collection_sizes),
        )

    def is_bottom(self) -> bool:
        return self._is_bottom

    def get(self, var: str) -> NumericProduct:
        """Get."""
        if var in self.variables:
            return self.variables[var]
        return NumericProduct.top()

    def set(self, var: str, value: NumericProduct) -> None:
        if value.is_bottom():
            self._is_bottom = True
        else:
            self.variables[var] = value

    def push(self, value: NumericProduct) -> None:
        self.stack.append(value)

    def pop(self) -> NumericProduct:
        """Pop."""
        if self.stack:
            return self.stack.pop()
        return NumericProduct.top()

    def peek(self, depth: int = 0) -> NumericProduct:
        """Peek."""
        idx = -(depth + 1)
        if abs(idx) <= len(self.stack):
            return self.stack[idx]
        return NumericProduct.top()

    def join(self, other: AbstractState) -> AbstractState:
        """Join."""
        if self._is_bottom:
            return other.copy()
        if other._is_bottom:
            return self.copy()
        result = AbstractState()
        all_vars = set(self.variables.keys()) | set(other.variables.keys())
        for var in all_vars:
            v1 = self.get(var)
            v2 = other.get(var)
            result.variables[var] = v1.join(v2)

        result.stack = [s1.join(s2) for s1, s2 in zip(self.stack, other.stack, strict=False)]

        all_collections = set(self.collection_sizes.keys()) | set(other.collection_sizes.keys())
        for coll in all_collections:
            c1 = self.collection_sizes.get(coll, NumericProduct.top())
            c2 = other.collection_sizes.get(coll, NumericProduct.top())
            result.collection_sizes[coll] = c1.join(c2)

        return result

    def widen(self, other: AbstractState) -> AbstractState:
        """Widen."""
        if self._is_bottom:
            return other.copy()
        if other._is_bottom:
            return self.copy()
        result = AbstractState()
        all_vars = set(self.variables.keys()) | set(other.variables.keys())
        for var in all_vars:
            v1 = self.get(var)
            v2 = other.get(var)
            result.variables[var] = v1.widen(v2)

        result.stack = [s1.widen(s2) for s1, s2 in zip(self.stack, other.stack, strict=False)]

        all_collections = set(self.collection_sizes.keys()) | set(other.collection_sizes.keys())
        for coll in all_collections:
            c1 = self.collection_sizes.get(coll, NumericProduct.top())
            c2 = other.collection_sizes.get(coll, NumericProduct.top())
            result.collection_sizes[coll] = c1.widen(c2)

        return result

    def leq(self, other: AbstractState) -> bool:
        """Check if self ⊆ other (every variable in self is ≤ the same variable in other)."""
        if self._is_bottom:
            return True
        if other._is_bottom:
            return False
        for var, value in self.variables.items():
            if not value.leq(other.get(var)):
                return False
        for var in other.variables:
            if var not in self.variables:
                if not NumericProduct.top().leq(other.get(var)):
                    return False
        return True


@dataclass
class AbstractWarning:
    """Generic warning from abstract interpretation."""

    kind: str
    message: str
    file: str
    line: int
    pc: int = 0


@dataclass
class DivisionByZeroWarning:
    """Warning for potential division by zero."""

    line: int
    pc: int
    variable: str
    divisor: NumericProduct
    confidence: str


@dataclass
class IndexOutOfBoundsWarning:
    """Warning for potential index out of bounds."""

    line: int
    pc: int
    collection: str
    index: NumericProduct
    size: NumericProduct
