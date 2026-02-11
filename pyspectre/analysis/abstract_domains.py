"""
Abstract Interpretation Layer for PySpectre.
Phase 22: Abstract domains for efficient analysis.
Sometimes symbolic execution is too precise (expensive).
Abstract interpretation provides sound over-approximation.
Supported Domains:
- Interval: x ∈ [lo, hi]
- Sign: x ∈ {neg, zero, pos, top}
- Parity: x ∈ {even, odd, top}
- Null: x ∈ {null, non_null, top}
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any,
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
    def from_concrete(cls, value: Any) -> T:
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
        if (
            self.lo is not None
            and self.hi is not None
            and self.lo > self.hi
            and not self._is_bottom
        ):
            self._is_bottom = True

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
        if other.lo is not None:
            if self.lo is None or other.lo < self.lo:
                new_lo = None
        new_hi = self.hi
        if other.hi is not None:
            if self.hi is None or other.hi > self.hi:
                new_hi = None
        return Interval(new_lo, new_hi)

    def to_z3_constraint(self, var: z3.ExprRef) -> z3.BoolRef:
        """Convert to Z3 constraint."""
        if self.is_bottom():
            return z3.BoolVal(False)
        if self.is_top():
            return z3.BoolVal(True)
        constraints = []
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
            result = self.lo * other.lo
            return Interval(result, result)
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
        if self.is_bottom():
            return "⊥"
        lo_str = str(self.lo) if self.lo is not None else "-∞"
        hi_str = str(self.hi) if self.hi is not None else "+∞"
        return f"[{lo_str}, {hi_str}]"


class SignValue(Enum):
    """Sign lattice values."""

    BOTTOM = auto()
    NEG = auto()
    ZERO = auto()
    POS = auto()
    NON_NEG = auto()
    NON_POS = auto()
    NON_ZERO = auto()
    TOP = auto()


@dataclass
class Sign(AbstractValue["Sign"]):
    r"""
    Sign abstract domain.
    Lattice:
           ⊤
         / | \
    non_neg non_zero non_pos
       |  \  /  |
      pos  \/  neg
       |   /\   |
       | zero  |
        \  |  /
          ⊥
    """

    value: SignValue = SignValue.TOP

    def is_top(self) -> bool:
        return self.value == SignValue.TOP

    def is_bottom(self) -> bool:
        return self.value == SignValue.BOTTOM

    def join(self, other: Sign) -> Sign:
        """Least upper bound."""
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        if self.value == other.value:
            return self
        v1, v2 = self.value, other.value
        if (v1, v2) in [(SignValue.POS, SignValue.ZERO), (SignValue.ZERO, SignValue.POS)]:
            return Sign(SignValue.NON_NEG)
        if (v1, v2) in [(SignValue.NEG, SignValue.ZERO), (SignValue.ZERO, SignValue.NEG)]:
            return Sign(SignValue.NON_POS)
        if (v1, v2) in [(SignValue.POS, SignValue.NEG), (SignValue.NEG, SignValue.POS)]:
            return Sign(SignValue.NON_ZERO)
        if v1 in (SignValue.NON_NEG, SignValue.NON_POS, SignValue.NON_ZERO):
            if v2 in (SignValue.POS, SignValue.ZERO, SignValue.NEG):
                return Sign(SignValue.TOP)
        if v2 in (SignValue.NON_NEG, SignValue.NON_POS, SignValue.NON_ZERO):
            if v1 in (SignValue.POS, SignValue.ZERO, SignValue.NEG):
                return Sign(SignValue.TOP)
        return Sign(SignValue.TOP)

    def meet(self, other: Sign) -> Sign:
        """Greatest lower bound."""
        if self.is_top():
            return other
        if other.is_top():
            return self
        if self.value == other.value:
            return self
        v1, v2 = self.value, other.value
        if v1 == SignValue.NON_NEG:
            if v2 == SignValue.NON_POS:
                return Sign(SignValue.ZERO)
            if v2 == SignValue.POS:
                return Sign(SignValue.POS)
            if v2 == SignValue.ZERO:
                return Sign(SignValue.ZERO)
        if v1 == SignValue.NON_POS:
            if v2 == SignValue.NON_NEG:
                return Sign(SignValue.ZERO)
            if v2 == SignValue.NEG:
                return Sign(SignValue.NEG)
            if v2 == SignValue.ZERO:
                return Sign(SignValue.ZERO)
        return Sign(SignValue.BOTTOM)

    def widen(self, other: Sign) -> Sign:
        """Widening (same as join for finite domain)."""
        return self.join(other)

    def to_z3_constraint(self, var: z3.ExprRef) -> z3.BoolRef:
        """Convert to Z3 constraint."""
        if self.value == SignValue.BOTTOM:
            return z3.BoolVal(False)
        if self.value == SignValue.TOP:
            return z3.BoolVal(True)
        if self.value == SignValue.NEG:
            return var < 0
        if self.value == SignValue.ZERO:
            return var == 0
        if self.value == SignValue.POS:
            return var > 0
        if self.value == SignValue.NON_NEG:
            return var >= 0
        if self.value == SignValue.NON_POS:
            return var <= 0
        if self.value == SignValue.NON_ZERO:
            return var != 0
        return z3.BoolVal(True)

    @classmethod
    def from_concrete(cls, value: int) -> Sign:
        """Create from concrete value."""
        if value < 0:
            return cls(SignValue.NEG)
        elif value == 0:
            return cls(SignValue.ZERO)
        else:
            return cls(SignValue.POS)

    @classmethod
    def top(cls) -> Sign:
        return cls(SignValue.TOP)

    @classmethod
    def bottom(cls) -> Sign:
        return cls(SignValue.BOTTOM)

    @classmethod
    def positive(cls) -> Sign:
        return cls(SignValue.POS)

    @classmethod
    def negative(cls) -> Sign:
        return cls(SignValue.NEG)

    @classmethod
    def zero(cls) -> Sign:
        return cls(SignValue.ZERO)

    @classmethod
    def non_negative(cls) -> Sign:
        return cls(SignValue.NON_NEG)

    @classmethod
    def non_positive(cls) -> Sign:
        return cls(SignValue.NON_POS)

    @classmethod
    def non_zero(cls) -> Sign:
        return cls(SignValue.NON_ZERO)

    def __repr__(self) -> str:
        return f"Sign({self.value.name})"


class ParityValue(Enum):
    """Parity lattice values."""

    BOTTOM = auto()
    EVEN = auto()
    ODD = auto()
    TOP = auto()


@dataclass
class Parity(AbstractValue["Parity"]):
    r"""
    Parity abstract domain.
    Lattice:
         ⊤
        / \
      even odd
        \ /
         ⊥
    """

    value: ParityValue = ParityValue.TOP

    def is_top(self) -> bool:
        return self.value == ParityValue.TOP

    def is_bottom(self) -> bool:
        return self.value == ParityValue.BOTTOM

    def join(self, other: Parity) -> Parity:
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        if self.value == other.value:
            return self
        return Parity(ParityValue.TOP)

    def meet(self, other: Parity) -> Parity:
        if self.is_top():
            return other
        if other.is_top():
            return self
        if self.value == other.value:
            return self
        return Parity(ParityValue.BOTTOM)

    def widen(self, other: Parity) -> Parity:
        return self.join(other)

    def to_z3_constraint(self, var: z3.ExprRef) -> z3.BoolRef:
        if self.value == ParityValue.BOTTOM:
            return z3.BoolVal(False)
        if self.value == ParityValue.TOP:
            return z3.BoolVal(True)
        if self.value == ParityValue.EVEN:
            return var % 2 == 0
        if self.value == ParityValue.ODD:
            return var % 2 == 1
        return z3.BoolVal(True)

    @classmethod
    def from_concrete(cls, value: int) -> Parity:
        if value % 2 == 0:
            return cls(ParityValue.EVEN)
        return cls(ParityValue.ODD)

    @classmethod
    def top(cls) -> Parity:
        return cls(ParityValue.TOP)

    @classmethod
    def bottom(cls) -> Parity:
        return cls(ParityValue.BOTTOM)

    @classmethod
    def even(cls) -> Parity:
        return cls(ParityValue.EVEN)

    @classmethod
    def odd(cls) -> Parity:
        return cls(ParityValue.ODD)

    def __add__(self, other: Parity) -> Parity:
        if self.is_bottom() or other.is_bottom():
            return Parity.bottom()
        if self.is_top() or other.is_top():
            return Parity.top()
        if self.value == other.value:
            return Parity.even()
        return Parity.odd()

    def __mul__(self, other: Parity) -> Parity:
        if self.is_bottom() or other.is_bottom():
            return Parity.bottom()
        if self.is_top() or other.is_top():
            return Parity.top()
        if self.value == ParityValue.EVEN or other.value == ParityValue.EVEN:
            return Parity.even()
        return Parity.odd()

    def __repr__(self) -> str:
        return f"Parity({self.value.name})"


class NullValue(Enum):
    """Null lattice values."""

    BOTTOM = auto()
    NULL = auto()
    NON_NULL = auto()
    TOP = auto()


@dataclass
class Null(AbstractValue["Null"]):
    r"""
    Null abstract domain for reference types.
    Lattice:
         ⊤
        / \
      null non_null
        \ /
         ⊥
    """

    value: NullValue = NullValue.TOP

    def is_top(self) -> bool:
        return self.value == NullValue.TOP

    def is_bottom(self) -> bool:
        return self.value == NullValue.BOTTOM

    def is_null(self) -> bool:
        return self.value == NullValue.NULL

    def is_non_null(self) -> bool:
        return self.value == NullValue.NON_NULL

    def may_be_null(self) -> bool:
        return self.value in (NullValue.NULL, NullValue.TOP)

    def join(self, other: Null) -> Null:
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        if self.value == other.value:
            return self
        return Null(NullValue.TOP)

    def meet(self, other: Null) -> Null:
        if self.is_top():
            return other
        if other.is_top():
            return self
        if self.value == other.value:
            return self
        return Null(NullValue.BOTTOM)

    def widen(self, other: Null) -> Null:
        return self.join(other)

    def to_z3_constraint(self, var: z3.ExprRef) -> z3.BoolRef:
        if self.value == NullValue.BOTTOM:
            return z3.BoolVal(False)
        if self.value == NullValue.TOP:
            return z3.BoolVal(True)
        if self.value == NullValue.NULL:
            return var == 0
        if self.value == NullValue.NON_NULL:
            return var != 0
        return z3.BoolVal(True)

    @classmethod
    def from_concrete(cls, value: Any) -> Null:
        if value is None:
            return cls(NullValue.NULL)
        return cls(NullValue.NON_NULL)

    @classmethod
    def top(cls) -> Null:
        return cls(NullValue.TOP)

    @classmethod
    def bottom(cls) -> Null:
        return cls(NullValue.BOTTOM)

    @classmethod
    def null(cls) -> Null:
        return cls(NullValue.NULL)

    @classmethod
    def non_null(cls) -> Null:
        return cls(NullValue.NON_NULL)

    def __repr__(self) -> str:
        return f"Null({self.value.name})"


@dataclass
class ProductDomain:
    """
    Product of multiple abstract domains.
    Combines interval, sign, parity, etc. for more precision.
    """

    interval: Interval = field(default_factory=Interval.top)
    sign: Sign = field(default_factory=Sign.top)
    parity: Parity = field(default_factory=Parity.top)
    null: Null | None = None

    def is_bottom(self) -> bool:
        """Bottom if any component is bottom."""
        return (
            self.interval.is_bottom()
            or self.sign.is_bottom()
            or self.parity.is_bottom()
            or (self.null is not None and self.null.is_bottom())
        )

    def join(self, other: ProductDomain) -> ProductDomain:
        """Component-wise join."""
        return ProductDomain(
            interval=self.interval.join(other.interval),
            sign=self.sign.join(other.sign),
            parity=self.parity.join(other.parity),
            null=(self.null.join(other.null) if self.null and other.null else None),
        )

    def meet(self, other: ProductDomain) -> ProductDomain:
        """Component-wise meet."""
        return ProductDomain(
            interval=self.interval.meet(other.interval),
            sign=self.sign.meet(other.sign),
            parity=self.parity.meet(other.parity),
            null=(self.null.meet(other.null) if self.null and other.null else None),
        )

    def widen(self, other: ProductDomain) -> ProductDomain:
        """Component-wise widen."""
        return ProductDomain(
            interval=self.interval.widen(other.interval),
            sign=self.sign.widen(other.sign),
            parity=self.parity.widen(other.parity),
            null=(self.null.widen(other.null) if self.null and other.null else None),
        )

    def to_z3_constraint(self, var: z3.ExprRef) -> z3.BoolRef:
        """Combine all constraints."""
        constraints = [
            self.interval.to_z3_constraint(var),
            self.sign.to_z3_constraint(var),
            self.parity.to_z3_constraint(var),
        ]
        if self.null is not None:
            constraints.append(self.null.to_z3_constraint(var))
        return z3.And(*constraints)

    @classmethod
    def from_concrete(cls, value: Any) -> ProductDomain:
        """Create from concrete value."""
        if isinstance(value, int):
            return cls(
                interval=Interval.from_concrete(value),
                sign=Sign.from_concrete(value),
                parity=Parity.from_concrete(value),
            )
        return cls()

    def refine(self) -> ProductDomain:
        """
        Reduce: make components consistent.
        For example, if interval is [1, 10] and sign is NEG,
        the result should be bottom.
        """
        if not self.interval.is_bottom() and not self.sign.is_bottom():
            if self.sign.value == SignValue.NEG:
                if self.interval.lo is not None and self.interval.lo >= 0:
                    return ProductDomain(interval=Interval.bottom())
            if self.sign.value == SignValue.POS:
                if self.interval.hi is not None and self.interval.hi <= 0:
                    return ProductDomain(interval=Interval.bottom())
            if self.sign.value == SignValue.ZERO:
                if not self.interval.contains(0):
                    return ProductDomain(interval=Interval.bottom())
        return self


@dataclass
class AbstractState:
    """
    Abstract state mapping variables to abstract values.
    """

    values: dict[str, ProductDomain] = field(default_factory=dict)

    def get(self, name: str) -> ProductDomain:
        """Get abstract value for variable."""
        return self.values.get(name, ProductDomain())

    def set(self, name: str, value: ProductDomain) -> None:
        """Set abstract value for variable."""
        self.values[name] = value

    def join(self, other: AbstractState) -> AbstractState:
        """Join two states."""
        keys1 = set(self.values.keys()) if self.values else set()
        keys2 = set(other.values.keys()) if other.values else set()
        all_vars = keys1 | keys2
        result = AbstractState()
        for var in all_vars:
            v1 = self.get(var)
            v2 = other.get(var)
            result.set(var, v1.join(v2))
        return result

    def widen(self, other: AbstractState) -> AbstractState:
        """Widen state."""
        all_vars = set(self.values.keys()) | set(other.values.keys())
        result = AbstractState()
        for var in all_vars:
            v1 = self.get(var)
            v2 = other.get(var)
            result.set(var, v1.widen(v2))
        return result

    def to_z3_constraints(self) -> list[z3.BoolRef]:
        """Convert to Z3 constraints."""
        constraints = []
        for name, value in self.values.items():
            var = z3.Int(name)
            constraints.append(value.to_z3_constraint(var))
        return constraints

    def copy(self) -> AbstractState:
        """Create a copy."""
        result = AbstractState()
        result.values = {k: v for k, v in self.values.items()}
        return result


class AbstractInterpreter:
    """
    Abstract interpreter for bytecode.
    Provides sound over-approximation of program behavior.
    """

    def __init__(self, widening_threshold: int = 3):
        self.widening_threshold = widening_threshold

    def analyze_assignment(
        self,
        state: AbstractState,
        target: str,
        value: ProductDomain,
    ) -> AbstractState:
        """Analyze an assignment."""
        result = state.copy()
        result.set(target, value)
        return result

    def analyze_binary_op(
        self,
        op: str,
        left: ProductDomain,
        right: ProductDomain,
    ) -> ProductDomain:
        """Analyze a binary operation."""
        if op == "+":
            return ProductDomain(
                interval=left.interval + right.interval,
                sign=self._add_signs(left.sign, right.sign),
                parity=left.parity + right.parity,
            )
        elif op == "-":
            return ProductDomain(
                interval=left.interval - right.interval,
                sign=self._sub_signs(left.sign, right.sign),
                parity=left.parity + right.parity,
            )
        elif op == "*":
            return ProductDomain(
                interval=left.interval * right.interval,
                sign=self._mul_signs(left.sign, right.sign),
                parity=left.parity * right.parity,
            )
        else:
            return ProductDomain()

    def _add_signs(self, s1: Sign, s2: Sign) -> Sign:
        """Sign of addition."""
        if s1.is_bottom() or s2.is_bottom():
            return Sign.bottom()
        if s1.is_top() or s2.is_top():
            return Sign.top()
        v1, v2 = s1.value, s2.value
        if v1 == v2 and v1 in (SignValue.POS, SignValue.NEG):
            return Sign(v1)
        if v1 == SignValue.ZERO:
            return s2
        if v2 == SignValue.ZERO:
            return s1
        return Sign.top()

    def _sub_signs(self, s1: Sign, s2: Sign) -> Sign:
        """Sign of subtraction."""
        if s1.is_bottom() or s2.is_bottom():
            return Sign.bottom()
        if s2.value == SignValue.ZERO:
            return s1
        if s1.value == SignValue.POS and s2.value == SignValue.NEG:
            return Sign.positive()
        if s1.value == SignValue.NEG and s2.value == SignValue.POS:
            return Sign.negative()
        return Sign.top()

    def _mul_signs(self, s1: Sign, s2: Sign) -> Sign:
        """Sign of multiplication."""
        if s1.is_bottom() or s2.is_bottom():
            return Sign.bottom()
        if s1.value == SignValue.ZERO or s2.value == SignValue.ZERO:
            return Sign.zero()
        v1, v2 = s1.value, s2.value
        if v1 in (SignValue.POS, SignValue.NEG) and v2 in (SignValue.POS, SignValue.NEG):
            if v1 == v2:
                return Sign.positive()
            else:
                return Sign.negative()
        return Sign.top()

    def analyze_comparison(
        self,
        op: str,
        left: ProductDomain,
        right: ProductDomain,
    ) -> tuple[ProductDomain, ProductDomain]:
        """
        Analyze a comparison, returning refined values for both sides.
        For example, if x < 10 is true, refine x's interval upper bound.
        """
        left_refined = left
        right_refined = right
        if op == "<":
            if right.interval.lo is not None:
                new_hi = right.interval.lo - 1
                left_refined = ProductDomain(
                    interval=left.interval.meet(Interval(None, new_hi)),
                    sign=left.sign,
                    parity=left.parity,
                )
        elif op == "<=":
            if right.interval.lo is not None:
                left_refined = ProductDomain(
                    interval=left.interval.meet(Interval(None, right.interval.lo)),
                    sign=left.sign,
                    parity=left.parity,
                )
        elif op == ">":
            if right.interval.hi is not None:
                new_lo = right.interval.hi + 1
                left_refined = ProductDomain(
                    interval=left.interval.meet(Interval(new_lo, None)),
                    sign=left.sign,
                    parity=left.parity,
                )
        elif op == ">=":
            if right.interval.hi is not None:
                left_refined = ProductDomain(
                    interval=left.interval.meet(Interval(right.interval.hi, None)),
                    sign=left.sign,
                    parity=left.parity,
                )
        return left_refined, right_refined

    def analyze_loop(
        self,
        init_state: AbstractState,
        body: Callable[[AbstractState], AbstractState],
        max_iterations: int = 100,
    ) -> AbstractState:
        """
        Analyze a loop with widening.
        Computes fixpoint of loop body.
        """
        state = init_state.copy()
        iteration = 0
        while iteration < max_iterations:
            new_state = body(state)
            if self._states_equal(state, new_state):
                break
            if iteration >= self.widening_threshold:
                state = state.widen(new_state)
            else:
                state = state.join(new_state)
            iteration += 1
        return state

    def _states_equal(self, s1: AbstractState, s2: AbstractState) -> bool:
        """Check if two states are equal."""
        keys1 = set(s1.values.keys()) if s1.values else set()
        keys2 = set(s2.values.keys()) if s2.values else set()
        all_vars = keys1 | keys2
        for var in all_vars:
            v1 = s1.get(var)
            v2 = s2.get(var)
            if v1 != v2:
                return False
        return True


__all__ = [
    "AbstractValue",
    "Interval",
    "Sign",
    "SignValue",
    "Parity",
    "ParityValue",
    "Null",
    "NullValue",
    "ProductDomain",
    "AbstractState",
    "AbstractInterpreter",
]
