"""Sign, Parity, and Null abstract domains.

Each domain provides lattice operations (join, meet, widen)
and conversion to Z3 constraints.
"""

from __future__ import annotations


from dataclasses import dataclass

from enum import Enum, auto

from typing import Any


import z3


from pysymex.analysis.abstract.domains_base import AbstractValue


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
                contained = {
                    SignValue.NON_NEG: {SignValue.POS, SignValue.ZERO},
                    SignValue.NON_POS: {SignValue.NEG, SignValue.ZERO},
                    SignValue.NON_ZERO: {SignValue.POS, SignValue.NEG},
                }

                if v2 in contained.get(v1, set()):
                    return Sign(v1)

                return Sign(SignValue.TOP)

        if v2 in (SignValue.NON_NEG, SignValue.NON_POS, SignValue.NON_ZERO):
            if v1 in (SignValue.POS, SignValue.ZERO, SignValue.NEG):
                contained = {
                    SignValue.NON_NEG: {SignValue.POS, SignValue.ZERO},
                    SignValue.NON_POS: {SignValue.NEG, SignValue.ZERO},
                    SignValue.NON_ZERO: {SignValue.POS, SignValue.NEG},
                }

                if v1 in contained.get(v2, set()):
                    return Sign(v2)

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

        _meet_table: dict[frozenset[SignValue], SignValue] = {
            frozenset({SignValue.NON_NEG, SignValue.NON_POS}): SignValue.ZERO,
            frozenset({SignValue.NON_NEG, SignValue.NON_ZERO}): SignValue.POS,
            frozenset({SignValue.NON_NEG, SignValue.POS}): SignValue.POS,
            frozenset({SignValue.NON_NEG, SignValue.ZERO}): SignValue.ZERO,
            frozenset({SignValue.NON_POS, SignValue.NON_ZERO}): SignValue.NEG,
            frozenset({SignValue.NON_POS, SignValue.NEG}): SignValue.NEG,
            frozenset({SignValue.NON_POS, SignValue.ZERO}): SignValue.ZERO,
            frozenset({SignValue.NON_ZERO, SignValue.POS}): SignValue.POS,
            frozenset({SignValue.NON_ZERO, SignValue.NEG}): SignValue.NEG,
            frozenset({SignValue.NON_ZERO, SignValue.ZERO}): SignValue.BOTTOM,
        }

        pair = frozenset({v1, v2})

        if pair in _meet_table:
            return Sign(_meet_table[pair])

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

        if self.value == ParityValue.EVEN or other.value == ParityValue.EVEN:
            return Parity.even()

        if self.is_top() or other.is_top():
            return Parity.top()

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
