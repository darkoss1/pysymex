"""Abstract value domains for the abstract interpretation framework.

Provides the core abstract domain hierarchy:
- AbstractValue (ABC)
- Sign enum + SignValue domain
- Interval domain
- Congruence domain
"""

from __future__ import annotations


from abc import ABC, abstractmethod

from dataclasses import dataclass

from enum import Enum, auto


class AbstractValue(ABC):
    """
    Base class for abstract values in an abstract domain.
    An abstract value represents a set of concrete values through
    sound over-approximation.
    """

    @abstractmethod
    def is_bottom(self) -> bool:
        """Check if this is the bottom element (empty set)."""

    @abstractmethod
    def is_top(self) -> bool:
        """Check if this is the top element (all values)."""

    @abstractmethod
    def join(self, other: AbstractValue) -> AbstractValue:
        """Compute the least upper bound (union)."""

    @abstractmethod
    def meet(self, other: AbstractValue) -> AbstractValue:
        """Compute the greatest lower bound (intersection)."""

    @abstractmethod
    def widen(self, other: AbstractValue) -> AbstractValue:
        """Widening operator for termination."""

    @abstractmethod
    def narrow(self, other: AbstractValue) -> AbstractValue:
        """Narrowing operator for precision."""

    @abstractmethod
    def leq(self, other: AbstractValue) -> bool:
        """Check if this is less than or equal to other (subset)."""


class Sign(Enum):
    """Sign abstract domain values."""

    BOTTOM = auto()

    NEGATIVE = auto()

    ZERO = auto()

    POSITIVE = auto()

    NON_NEGATIVE = auto()

    NON_POSITIVE = auto()

    NON_ZERO = auto()

    TOP = auto()


@dataclass(frozen=True)
class SignValue(AbstractValue):
    """
    Sign abstract domain for numeric values.
    Tracks whether values are positive, negative, or zero.
    """

    sign: Sign

    @classmethod
    def bottom(cls) -> SignValue:
        return cls(Sign.BOTTOM)

    @classmethod
    def top(cls) -> SignValue:
        return cls(Sign.TOP)

    @classmethod
    def from_const(cls, value: int | float) -> SignValue:
        """Create sign from concrete constant."""

        if value < 0:
            return cls(Sign.NEGATIVE)

        elif value > 0:
            return cls(Sign.POSITIVE)

        else:
            return cls(Sign.ZERO)

    def is_bottom(self) -> bool:
        return self.sign == Sign.BOTTOM

    def is_top(self) -> bool:
        return self.sign == Sign.TOP

    def may_be_zero(self) -> bool:
        """Check if value might be zero."""

        return self.sign in {Sign.ZERO, Sign.NON_NEGATIVE, Sign.NON_POSITIVE, Sign.TOP}

    def must_be_positive(self) -> bool:
        """Check if value must be positive."""

        return self.sign == Sign.POSITIVE

    def must_be_negative(self) -> bool:
        """Check if value must be negative."""

        return self.sign == Sign.NEGATIVE

    def must_be_non_zero(self) -> bool:
        """Check if value cannot be zero."""

        return self.sign in {Sign.NEGATIVE, Sign.POSITIVE, Sign.NON_ZERO}

    def join(self, other: AbstractValue) -> SignValue:
        if not isinstance(other, SignValue):
            return SignValue.top()

        s1, s2 = self.sign, other.sign

        if s1 == Sign.BOTTOM:
            return other

        if s2 == Sign.BOTTOM:
            return self

        if s1 == Sign.TOP or s2 == Sign.TOP:
            return SignValue.top()

        if s1 == s2:
            return self

        join_table: dict[frozenset[Sign], Sign] = {
            frozenset({Sign.NEGATIVE, Sign.ZERO}): Sign.NON_POSITIVE,
            frozenset({Sign.POSITIVE, Sign.ZERO}): Sign.NON_NEGATIVE,
            frozenset({Sign.NEGATIVE, Sign.POSITIVE}): Sign.NON_ZERO,
            frozenset({Sign.POSITIVE, Sign.NON_NEGATIVE}): Sign.NON_NEGATIVE,
            frozenset({Sign.NEGATIVE, Sign.NON_POSITIVE}): Sign.NON_POSITIVE,
            frozenset({Sign.POSITIVE, Sign.NON_ZERO}): Sign.NON_ZERO,
            frozenset({Sign.NEGATIVE, Sign.NON_ZERO}): Sign.NON_ZERO,
            frozenset({Sign.ZERO, Sign.NON_NEGATIVE}): Sign.NON_NEGATIVE,
            frozenset({Sign.ZERO, Sign.NON_POSITIVE}): Sign.NON_POSITIVE,
            frozenset({Sign.NON_NEGATIVE, Sign.NEGATIVE}): Sign.TOP,
            frozenset({Sign.NON_POSITIVE, Sign.POSITIVE}): Sign.TOP,
            frozenset({Sign.NON_ZERO, Sign.ZERO}): Sign.TOP,
            frozenset({Sign.NON_NEGATIVE, Sign.NON_POSITIVE}): Sign.TOP,
            frozenset({Sign.NON_NEGATIVE, Sign.NON_ZERO}): Sign.TOP,
            frozenset({Sign.NON_POSITIVE, Sign.NON_ZERO}): Sign.TOP,
        }

        key = frozenset({s1, s2})

        if key in join_table:
            return SignValue(join_table[key])

        return SignValue.top()

    def meet(self, other: AbstractValue) -> SignValue:
        if not isinstance(other, SignValue):
            return self

        s1, s2 = self.sign, other.sign

        if s1 == Sign.TOP:
            return other

        if s2 == Sign.TOP:
            return self

        if s1 == Sign.BOTTOM or s2 == Sign.BOTTOM:
            return SignValue.bottom()

        if s1 == s2:
            return self

        if s1 == Sign.NON_NEGATIVE and s2 == Sign.NON_POSITIVE:
            return SignValue(Sign.ZERO)

        if s1 == Sign.NON_POSITIVE and s2 == Sign.NON_NEGATIVE:
            return SignValue(Sign.ZERO)

        return SignValue.bottom()

    def widen(self, other: AbstractValue) -> SignValue:
        return self.join(other)

    def narrow(self, other: AbstractValue) -> SignValue:
        return self.meet(other)

    def leq(self, other: AbstractValue) -> bool:
        if not isinstance(other, SignValue):
            return False

        if self.sign == Sign.BOTTOM:
            return True

        if other.sign == Sign.TOP:
            return True

        return self.sign == other.sign

    def add(self, other: SignValue) -> SignValue:
        """Abstract addition."""

        if self.is_bottom() or other.is_bottom():
            return SignValue.bottom()

        s1, s2 = self.sign, other.sign

        if s1 == Sign.ZERO:
            return other

        if s2 == Sign.ZERO:
            return self

        if s1 == Sign.POSITIVE and s2 == Sign.POSITIVE:
            return SignValue(Sign.POSITIVE)

        if s1 == Sign.NEGATIVE and s2 == Sign.NEGATIVE:
            return SignValue(Sign.NEGATIVE)

        return SignValue.top()

    def sub(self, other: SignValue) -> SignValue:
        """Abstract subtraction."""

        return self.add(other.neg())

    def neg(self) -> SignValue:
        """Abstract negation."""

        if self.sign == Sign.POSITIVE:
            return SignValue(Sign.NEGATIVE)

        if self.sign == Sign.NEGATIVE:
            return SignValue(Sign.POSITIVE)

        if self.sign == Sign.ZERO:
            return self

        if self.sign == Sign.NON_NEGATIVE:
            return SignValue(Sign.NON_POSITIVE)

        if self.sign == Sign.NON_POSITIVE:
            return SignValue(Sign.NON_NEGATIVE)

        return SignValue(self.sign)

    def mul(self, other: SignValue) -> SignValue:
        """Abstract multiplication."""

        if self.is_bottom() or other.is_bottom():
            return SignValue.bottom()

        s1, s2 = self.sign, other.sign

        if s1 == Sign.ZERO or s2 == Sign.ZERO:
            return SignValue(Sign.ZERO)

        if (s1 == Sign.POSITIVE and s2 == Sign.POSITIVE) or (
            s1 == Sign.NEGATIVE and s2 == Sign.NEGATIVE
        ):
            return SignValue(Sign.POSITIVE)

        if (s1 == Sign.POSITIVE and s2 == Sign.NEGATIVE) or (
            s1 == Sign.NEGATIVE and s2 == Sign.POSITIVE
        ):
            return SignValue(Sign.NEGATIVE)

        return SignValue.top()

    def div(self, other: SignValue) -> tuple[SignValue, bool]:
        """Abstract division. Returns (result, may_raise)."""

        if self.is_bottom() or other.is_bottom():
            return SignValue.bottom(), False

        may_raise = other.may_be_zero()

        if other.must_be_non_zero():
            return self.mul(other), False

        return SignValue.top(), may_raise


@dataclass(frozen=True)
class Interval(AbstractValue):
    """
    Interval abstract domain [low, high].
    Represents values in the range [low, high] inclusive.
    """

    low: int | None

    high: int | None

    _is_bottom: bool = False

    @classmethod
    def bottom(cls) -> Interval:
        return cls(None, None, _is_bottom=True)

    @classmethod
    def top(cls) -> Interval:
        return cls(None, None, _is_bottom=False)

    @classmethod
    def const(cls, value: int) -> Interval:
        return cls(value, value)

    @classmethod
    def range(cls, low: int | None, high: int | None) -> Interval:
        if low is not None and high is not None and low > high:
            return cls.bottom()

        return cls(low, high)

    @classmethod
    def non_negative(cls) -> Interval:
        return cls(0, None)

    @classmethod
    def positive(cls) -> Interval:
        return cls(1, None)

    def is_bottom(self) -> bool:
        return self._is_bottom

    def is_top(self) -> bool:
        return not self._is_bottom and self.low is None and self.high is None

    def is_const(self) -> bool:
        """Check if this interval contains exactly one value."""

        return self.low is not None and self.high is not None and self.low == self.high

    def get_const(self) -> int | None:
        """Get constant value if this is a singleton interval."""

        if self.is_const():
            return self.low

        return None

    def contains(self, value: int) -> bool:
        """Check if the interval contains a specific value."""

        if self._is_bottom:
            return False

        if self.low is not None and value < self.low:
            return False

        if self.high is not None and value > self.high:
            return False

        return True

    def may_be_zero(self) -> bool:
        """Check if zero is in the interval."""

        return self.contains(0)

    def must_be_positive(self) -> bool:
        """Check if all values are positive."""

        return self.low is not None and self.low > 0

    def must_be_negative(self) -> bool:
        """Check if all values are negative."""

        return self.high is not None and self.high < 0

    def must_be_non_zero(self) -> bool:
        """Check if zero is definitely not in the interval."""

        if self._is_bottom:
            return True

        return not self.contains(0)

    def join(self, other: AbstractValue) -> Interval:
        if not isinstance(other, Interval):
            return Interval.top()

        if self._is_bottom:
            return other

        if other._is_bottom:
            return self

        new_low: int | None

        new_high: int | None

        if self.low is None or other.low is None:
            new_low = None

        else:
            new_low = min(self.low, other.low)

        if self.high is None or other.high is None:
            new_high = None

        else:
            new_high = max(self.high, other.high)

        return Interval(new_low, new_high)

    def meet(self, other: AbstractValue) -> Interval:
        if not isinstance(other, Interval):
            return self

        if self._is_bottom or other._is_bottom:
            return Interval.bottom()

        new_low: int | None

        new_high: int | None

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
            return Interval.bottom()

        return Interval(new_low, new_high)

    def widen(self, other: AbstractValue) -> Interval:
        """Standard interval widening."""

        if not isinstance(other, Interval):
            return Interval.top()

        if self._is_bottom:
            return other

        if other._is_bottom:
            return self

        new_low: int | None

        new_high: int | None

        if other.low is not None:
            if self.low is None or other.low < self.low:
                new_low = None

            else:
                new_low = self.low

        else:
            new_low = None

        if other.high is not None:
            if self.high is None or other.high > self.high:
                new_high = None

            else:
                new_high = self.high

        else:
            new_high = None

        return Interval(new_low, new_high)

    def narrow(self, other: AbstractValue) -> Interval:
        """Standard interval narrowing."""

        if not isinstance(other, Interval):
            return self

        new_low = self.low if self.low is not None else other.low

        new_high = self.high if self.high is not None else other.high

        return Interval(new_low, new_high)

    def leq(self, other: AbstractValue) -> bool:
        if not isinstance(other, Interval):
            return False

        if self._is_bottom:
            return True

        if other._is_bottom:
            return False

        if other.low is not None:
            if self.low is None or self.low < other.low:
                return False

        if other.high is not None:
            if self.high is None or self.high > other.high:
                return False

        return True

    def add(self, other: Interval) -> Interval:
        """Interval addition."""

        if self._is_bottom or other._is_bottom:
            return Interval.bottom()

        new_low: int | None = None

        new_high: int | None = None

        if self.low is not None and other.low is not None:
            new_low = self.low + other.low

        if self.high is not None and other.high is not None:
            new_high = self.high + other.high

        return Interval(new_low, new_high)

    def sub(self, other: Interval) -> Interval:
        """Interval subtraction."""

        if self._is_bottom or other._is_bottom:
            return Interval.bottom()

        new_low: int | None = None

        new_high: int | None = None

        if self.low is not None and other.high is not None:
            new_low = self.low - other.high

        if self.high is not None and other.low is not None:
            new_high = self.high - other.low

        return Interval(new_low, new_high)

    def neg(self) -> Interval:
        """Interval negation."""

        if self._is_bottom:
            return Interval.bottom()

        new_low = -self.high if self.high is not None else None

        new_high = -self.low if self.low is not None else None

        return Interval(new_low, new_high)

    def mul(self, other: Interval) -> Interval:
        """Interval multiplication."""

        if self._is_bottom or other._is_bottom:
            return Interval.bottom()

        if self.is_const() and other.is_const():
            assert self.low is not None and other.low is not None

            return Interval.const(self.low * other.low)

        if self.is_top() or other.is_top():
            return Interval.top()

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

            return Interval(min(products), max(products))

        return Interval.top()

    def div(self, other: Interval) -> tuple[Interval, bool]:
        """Interval division. Returns (result, may_raise_div_by_zero)."""

        if self._is_bottom or other._is_bottom:
            return Interval.bottom(), False

        may_raise = other.contains(0)

        if other.is_const() and other.low == 0:
            return Interval.bottom(), True

        if other.is_const() and other.low is not None and other.low > 0:
            if self.is_const() and self.low is not None:
                return Interval.const(self.low // other.low), False

        return Interval.top(), may_raise


@dataclass(frozen=True)
class Congruence(AbstractValue):
    """
    Congruence abstract domain: values of the form a*x + b.
    Represents values that satisfy: value ≡ remainder (mod modulus)
    """

    modulus: int | None

    remainder: int

    _is_bottom: bool = False

    @classmethod
    def bottom(cls) -> Congruence:
        return cls(None, 0, _is_bottom=True)

    @classmethod
    def top(cls) -> Congruence:
        return cls(None, 0)

    @classmethod
    def const(cls, value: int) -> Congruence:
        """Exact value: value ≡ value (mod 0), or equivalently mod=0, rem=value."""

        return cls(0, value)

    @classmethod
    def mod(cls, modulus: int, remainder: int = 0) -> Congruence:
        """Values ≡ remainder (mod modulus)."""

        if modulus == 0:
            return cls(0, remainder)

        return cls(modulus, remainder % modulus)

    def is_bottom(self) -> bool:
        return self._is_bottom

    def is_top(self) -> bool:
        return not self._is_bottom and self.modulus is None

    def is_const(self) -> bool:
        return not self._is_bottom and self.modulus == 0

    def get_const(self) -> int | None:
        if self.is_const():
            return self.remainder

        return None

    def may_be_zero(self) -> bool:
        if self._is_bottom:
            return False

        if self.modulus is None:
            return True

        if self.modulus == 0:
            return self.remainder == 0

        return self.remainder == 0

    def must_be_even(self) -> bool:
        if self._is_bottom:
            return True

        if self.modulus is None:
            return False

        if self.modulus == 0:
            return self.remainder % 2 == 0

        return self.modulus % 2 == 0 and self.remainder % 2 == 0

    def join(self, other: AbstractValue) -> Congruence:
        if not isinstance(other, Congruence):
            return Congruence.top()

        if self._is_bottom:
            return other

        if other._is_bottom:
            return self

        if self.modulus is None or other.modulus is None:
            return Congruence.top()

        import math

        diff = abs(self.remainder - other.remainder)

        new_mod = math.gcd(self.modulus, other.modulus)

        if diff != 0:
            new_mod = math.gcd(new_mod, diff)

        if new_mod == 0:
            if self.remainder != other.remainder:
                return Congruence.top()

            return self

        new_rem = self.remainder % new_mod

        return Congruence(new_mod, new_rem)

    def meet(self, other: AbstractValue) -> Congruence:
        if not isinstance(other, Congruence):
            return self

        if self._is_bottom or other._is_bottom:
            return Congruence.bottom()

        if self.modulus is None:
            return other

        if other.modulus is None:
            return self

        import math

        g = math.gcd(self.modulus if self.modulus else 1, other.modulus if other.modulus else 1)

        if (self.remainder - other.remainder) % g != 0:
            return Congruence.bottom()

        return self

    def widen(self, other: AbstractValue) -> Congruence:
        return self.join(other)

    def narrow(self, other: AbstractValue) -> Congruence:
        return self.meet(other)

    def leq(self, other: AbstractValue) -> bool:
        if not isinstance(other, Congruence):
            return False

        if self._is_bottom:
            return True

        if other.modulus is None:
            return True

        if self.modulus is None:
            return False

        if other.modulus == 0:
            return self.modulus == 0 and self.remainder == other.remainder

        if self.modulus != 0 and self.modulus % other.modulus != 0:
            return False

        return self.remainder % other.modulus == other.remainder
