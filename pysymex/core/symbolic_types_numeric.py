"""Symbolic numeric types: Bool, Int, Float.

These three types are mutually referential (e.g. Int comparisons return Bool,
Bool equality checks reference Int, Float coerces with Int), so they live
in the same module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import z3

from .symbolic_types_base import SymbolicType, TypeTag, fresh_name

if TYPE_CHECKING:
    from .types import SymbolicValue

_BV_WIDTH: int = 64


@dataclass
class SymbolicBool(SymbolicType):
    """Symbolic boolean value.
    Uses Z3 Bool sort directly.
    """

    z3_bool: z3.BoolRef
    _name: str = field(default="")

    __hash__ = object.__hash__

    def __post_init__(self):
        if not self._name:
            self._name = fresh_name("bool")

    @property
    def type_tag(self) -> TypeTag:
        """Property returning the type_tag."""
        return TypeTag.BOOL

    @property
    def name(self) -> str:
        return self._name

    def to_z3(self) -> z3.ExprRef:
        return self.z3_bool

    def is_truthy(self) -> z3.BoolRef:
        return self.z3_bool

    def is_falsy(self) -> z3.BoolRef:
        return z3.Not(self.z3_bool)

    def symbolic_eq(self, other: SymbolicType) -> z3.BoolRef:
        """Symbolic eq."""
        if isinstance(other, SymbolicBool):
            return self.z3_bool == other.z3_bool
        elif isinstance(other, SymbolicInt):
            return z3.If(self.z3_bool, other.z3_int == 1, other.z3_int == 0)
        return z3.BoolVal(False)

    def __and__(self, other: SymbolicBool) -> SymbolicBool:
        return SymbolicBool(z3.And(self.z3_bool, other.z3_bool))

    def __or__(self, other: SymbolicBool) -> SymbolicBool:
        return SymbolicBool(z3.Or(self.z3_bool, other.z3_bool))

    def __invert__(self) -> SymbolicBool:
        return SymbolicBool(z3.Not(self.z3_bool))

    def __xor__(self, other: SymbolicBool) -> SymbolicBool:
        return SymbolicBool(z3.Xor(self.z3_bool, other.z3_bool))

    @staticmethod
    def symbolic(name: str | None = None) -> SymbolicBool:
        """Create a fresh symbolic boolean."""
        name = name or fresh_name("bool")
        return SymbolicBool(z3.Bool(name), name)

    @staticmethod
    def concrete(value: bool) -> SymbolicBool:
        """Create a concrete boolean."""
        return SymbolicBool(z3.BoolVal(value), str(value))

    def as_unified(self) -> SymbolicValue:
        """As unified."""
        from .types import Z3_FALSE, Z3_TRUE, SymbolicValue

        return SymbolicValue(
            _name=self._name,
            z3_int=z3.If(self.z3_bool, z3.IntVal(1), z3.IntVal(0)),
            is_int=Z3_FALSE,
            z3_bool=self.z3_bool,
            is_bool=Z3_TRUE,
            is_path=Z3_FALSE,
        )


@dataclass
class SymbolicInt(SymbolicType):
    """Symbolic integer value.
    Uses Z3 Int sort. Supports full integer arithmetic.
    """

    z3_int: z3.ArithRef
    _name: str = field(default="")
    _bv_cache: z3.BitVecRef | None = field(default=None, init=False, repr=False, compare=False)

    __hash__ = object.__hash__

    def __post_init__(self):
        if not self._name:
            self._name = fresh_name("int")

    @property
    def type_tag(self) -> TypeTag:
        """Property returning the type_tag."""
        return TypeTag.INT

    @property
    def name(self) -> str:
        return self._name

    def to_z3(self) -> z3.ExprRef:
        return self.z3_int

    @property
    def value(self) -> z3.ArithRef:
        """Expose the underlying Z3 integer expression."""
        return self.z3_int

    @property
    def as_bv(self) -> z3.BitVecRef:
        """Return cached 64-bit BitVec form of this integer."""
        if self._bv_cache is None:
            self._bv_cache = z3.Int2BV(self.z3_int, _BV_WIDTH)
        return self._bv_cache

    def is_truthy(self) -> z3.BoolRef:
        return self.z3_int != 0

    def is_falsy(self) -> z3.BoolRef:
        return self.z3_int == 0

    def symbolic_eq(self, other: SymbolicType) -> z3.BoolRef:
        """Symbolic eq."""
        if isinstance(other, SymbolicInt):
            return self.z3_int == other.z3_int
        elif isinstance(other, SymbolicBool):
            return z3.If(other.z3_bool, self.z3_int == 1, self.z3_int == 0)
        elif isinstance(other, SymbolicFloat):
            return z3.ToReal(self.z3_int) == other.z3_real
        return z3.BoolVal(False)

    def __add__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicInt | SymbolicFloat:
        if isinstance(other, SymbolicFloat):
            return SymbolicFloat(z3.ToReal(self.z3_int) + other.z3_real)
        return SymbolicInt(self.z3_int + other.z3_int)

    def __radd__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicInt | SymbolicFloat:
        return self.__add__(other)

    def __sub__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicInt | SymbolicFloat:
        if isinstance(other, SymbolicFloat):
            return SymbolicFloat(z3.ToReal(self.z3_int) - other.z3_real)
        return SymbolicInt(self.z3_int - other.z3_int)

    def __rsub__(self, other: SymbolicInt) -> SymbolicInt:
        return SymbolicInt(other.z3_int - self.z3_int)

    def __mul__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicInt | SymbolicFloat:
        if isinstance(other, SymbolicFloat):
            return SymbolicFloat(z3.ToReal(self.z3_int) * other.z3_real)
        return SymbolicInt(self.z3_int * other.z3_int)

    def __rmul__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicInt | SymbolicFloat:
        return self.__mul__(other)

    def __neg__(self) -> SymbolicInt:
        return SymbolicInt(-self.z3_int)

    def __pos__(self) -> SymbolicInt:
        return self

    def __abs__(self) -> SymbolicInt:
        return SymbolicInt(z3.If(self.z3_int >= 0, self.z3_int, -self.z3_int))

    def __mod__(self, other: SymbolicInt) -> SymbolicInt:
        divisor = other.z3_int
        if z3.is_int_value(divisor) and divisor.as_long() == 0:
            raise ZeroDivisionError("integer modulo by zero")
        safe_divisor = z3.If(divisor == 0, z3.IntVal(1), divisor)
        floor_div = z3.ToInt(z3.ToReal(self.z3_int) / z3.ToReal(safe_divisor))
        return SymbolicInt(self.z3_int - floor_div * safe_divisor)

    def __floordiv__(self, other: SymbolicInt) -> SymbolicInt:
        divisor = other.z3_int
        if z3.is_int_value(divisor) and divisor.as_long() == 0:
            raise ZeroDivisionError("integer division by zero")
        safe_divisor = z3.If(divisor == 0, z3.IntVal(1), divisor)
        return SymbolicInt(z3.ToInt(z3.ToReal(self.z3_int) / z3.ToReal(safe_divisor)))

    def __truediv__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicFloat:
        if isinstance(other, SymbolicFloat):
            denom = other.z3_real
            if z3.is_rational_value(denom) and denom.numerator_as_long() == 0:
                raise ZeroDivisionError("float division by zero")
            safe_denom = z3.If(denom == 0, z3.RealVal(1), denom)
            return SymbolicFloat(z3.ToReal(self.z3_int) / safe_denom)
        denom_int = other.z3_int
        if z3.is_int_value(denom_int) and denom_int.as_long() == 0:
            raise ZeroDivisionError("division by zero")
        denom = z3.ToReal(denom_int)
        safe_denom = z3.If(denom == 0, z3.RealVal(1), denom)
        return SymbolicFloat(z3.ToReal(self.z3_int) / safe_denom)

    def __pow__(self, other: SymbolicInt) -> SymbolicInt:
        return SymbolicInt(self.z3_int**other.z3_int)

    def __lt__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicBool:
        if isinstance(other, SymbolicFloat):
            return SymbolicBool(z3.ToReal(self.z3_int) < other.z3_real)
        return SymbolicBool(self.z3_int < other.z3_int)

    def __le__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicBool:
        if isinstance(other, SymbolicFloat):
            return SymbolicBool(z3.ToReal(self.z3_int) <= other.z3_real)
        return SymbolicBool(self.z3_int <= other.z3_int)

    def __gt__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicBool:
        if isinstance(other, SymbolicFloat):
            return SymbolicBool(z3.ToReal(self.z3_int) > other.z3_real)
        return SymbolicBool(self.z3_int > other.z3_int)

    def __ge__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicBool:
        if isinstance(other, SymbolicFloat):
            return SymbolicBool(z3.ToReal(self.z3_int) >= other.z3_real)
        return SymbolicBool(self.z3_int >= other.z3_int)

    def __eq__(self, other: object) -> SymbolicBool:
        if isinstance(other, SymbolicInt):
            return SymbolicBool(self.z3_int == other.z3_int)
        elif isinstance(other, SymbolicFloat):
            return SymbolicBool(z3.ToReal(self.z3_int) == other.z3_real)
        return SymbolicBool.concrete(False)

    def __ne__(self, other: object) -> SymbolicBool:
        eq = self.__eq__(other)
        return SymbolicBool(z3.Not(eq.z3_bool))

    def __and__(self, other: SymbolicInt) -> SymbolicInt:
        bv_result = self.as_bv & other.as_bv
        return SymbolicInt(z3.BV2Int(bv_result, is_signed=True))

    def __or__(self, other: SymbolicInt) -> SymbolicInt:
        bv_result = self.as_bv | other.as_bv
        return SymbolicInt(z3.BV2Int(bv_result, is_signed=True))

    def __xor__(self, other: SymbolicInt) -> SymbolicInt:
        bv_result = self.as_bv ^ other.as_bv
        return SymbolicInt(z3.BV2Int(bv_result, is_signed=True))

    def __invert__(self) -> SymbolicInt:
        bv_result = ~self.as_bv
        return SymbolicInt(z3.BV2Int(bv_result, is_signed=True))

    def __lshift__(self, other: SymbolicInt) -> SymbolicInt:
        bv_result = self.as_bv << other.as_bv
        return SymbolicInt(z3.BV2Int(bv_result, is_signed=True))

    def __rshift__(self, other: SymbolicInt) -> SymbolicInt:
        bv_result = self.as_bv >> other.as_bv
        return SymbolicInt(z3.BV2Int(bv_result, is_signed=True))

    @staticmethod
    def symbolic(name: str | None = None) -> SymbolicInt:
        """Create a fresh symbolic integer."""
        name = name or fresh_name("int")
        return SymbolicInt(z3.Int(name), name)

    @staticmethod
    def concrete(value: int) -> SymbolicInt:
        """Create a concrete integer."""
        return SymbolicInt(z3.IntVal(value), str(value))

    def as_unified(self) -> SymbolicValue:
        """As unified."""
        from .types import Z3_FALSE, Z3_TRUE, SymbolicValue

        return SymbolicValue(
            _name=self._name,
            z3_int=self.z3_int,
            is_int=Z3_TRUE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            is_path=Z3_FALSE,
        )


@dataclass
class SymbolicFloat(SymbolicType):
    """Symbolic floating-point value.
    Uses Z3 Real sort for exact rational arithmetic.
    Note: This doesn't model IEEE 754 floating-point exactly.
    """

    z3_real: z3.ArithRef
    _name: str = field(default="")

    __hash__ = object.__hash__

    def __post_init__(self):
        if not self._name:
            self._name = fresh_name("float")

    @property
    def type_tag(self) -> TypeTag:
        """Property returning the type_tag."""
        return TypeTag.FLOAT

    @property
    def name(self) -> str:
        return self._name

    def to_z3(self) -> z3.ExprRef:
        return self.z3_real

    def is_truthy(self) -> z3.BoolRef:
        return self.z3_real != 0

    def is_falsy(self) -> z3.BoolRef:
        return self.z3_real == 0

    def symbolic_eq(self, other: SymbolicType) -> z3.BoolRef:
        """Symbolic eq."""
        if isinstance(other, SymbolicFloat):
            return self.z3_real == other.z3_real
        elif isinstance(other, SymbolicInt):
            return self.z3_real == z3.ToReal(other.z3_int)
        return z3.BoolVal(False)

    def __add__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicFloat:
        if isinstance(other, SymbolicInt):
            return SymbolicFloat(self.z3_real + z3.ToReal(other.z3_int))
        return SymbolicFloat(self.z3_real + other.z3_real)

    def __radd__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicFloat:
        return self.__add__(other)

    def __sub__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicFloat:
        if isinstance(other, SymbolicInt):
            return SymbolicFloat(self.z3_real - z3.ToReal(other.z3_int))
        return SymbolicFloat(self.z3_real - other.z3_real)

    def __rsub__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicFloat:
        if isinstance(other, SymbolicInt):
            return SymbolicFloat(z3.ToReal(other.z3_int) - self.z3_real)
        return SymbolicFloat(other.z3_real - self.z3_real)

    def __mul__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicFloat:
        if isinstance(other, SymbolicInt):
            return SymbolicFloat(self.z3_real * z3.ToReal(other.z3_int))
        return SymbolicFloat(self.z3_real * other.z3_real)

    def __rmul__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicFloat:
        return self.__mul__(other)

    def __truediv__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicFloat:
        if isinstance(other, SymbolicInt):
            denom = other.z3_int
            if z3.is_int_value(denom) and denom.as_long() == 0:
                raise ZeroDivisionError("float division by zero")
            return SymbolicFloat(self.z3_real / z3.ToReal(denom))
        denom = other.z3_real
        if z3.is_rational_value(denom) and denom.numerator_as_long() == 0:
            raise ZeroDivisionError("float division by zero")
        return SymbolicFloat(self.z3_real / denom)

    def __neg__(self) -> SymbolicFloat:
        return SymbolicFloat(-self.z3_real)

    def __pos__(self) -> SymbolicFloat:
        return self

    def __abs__(self) -> SymbolicFloat:
        return SymbolicFloat(z3.If(self.z3_real >= 0, self.z3_real, -self.z3_real))

    def __lt__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicBool:
        if isinstance(other, SymbolicInt):
            return SymbolicBool(self.z3_real < z3.ToReal(other.z3_int))
        return SymbolicBool(self.z3_real < other.z3_real)

    def __le__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicBool:
        if isinstance(other, SymbolicInt):
            return SymbolicBool(self.z3_real <= z3.ToReal(other.z3_int))
        return SymbolicBool(self.z3_real <= other.z3_real)

    def __gt__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicBool:
        if isinstance(other, SymbolicInt):
            return SymbolicBool(self.z3_real > z3.ToReal(other.z3_int))
        return SymbolicBool(self.z3_real > other.z3_real)

    def __ge__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicBool:
        if isinstance(other, SymbolicInt):
            return SymbolicBool(self.z3_real >= z3.ToReal(other.z3_int))
        return SymbolicBool(self.z3_real >= other.z3_real)

    def __eq__(self, other: object) -> SymbolicBool:
        if isinstance(other, SymbolicFloat):
            return SymbolicBool(self.z3_real == other.z3_real)
        elif isinstance(other, SymbolicInt):
            return SymbolicBool(self.z3_real == z3.ToReal(other.z3_int))
        return SymbolicBool.concrete(False)

    def __ne__(self, other: object) -> SymbolicBool:
        eq = self.__eq__(other)
        return SymbolicBool(z3.Not(eq.z3_bool))

    def to_int(self) -> SymbolicInt:
        """Convert to integer (truncate toward zero — matches Python int()).

        z3.ToInt() applies floor (rounds toward -inf), which disagrees with
        Python's int() for negative non-integers:  int(-1.5) == -1  but
        ToInt(-1.5) == -2.  Correct formula: trunc(x) = sign(x)*floor(|x|).
        """
        abs_floor = z3.ToInt(z3.If(self.z3_real >= 0, self.z3_real, -self.z3_real))
        sign = z3.If(self.z3_real < 0, z3.IntVal(-1), z3.IntVal(1))
        return SymbolicInt(abs_floor * sign)

    @staticmethod
    def symbolic(name: str | None = None) -> SymbolicFloat:
        """Create a fresh symbolic float."""
        name = name or fresh_name("float")
        return SymbolicFloat(z3.Real(name), name)

    @staticmethod
    def concrete(value: float) -> SymbolicFloat:
        """Create a concrete float."""
        return SymbolicFloat(z3.RealVal(value), str(value))

    def as_unified(self) -> SymbolicValue:
        """As unified."""
        from .types import Z3_FALSE, SymbolicValue

        # Use truncation toward zero (matching to_int / Python int()),
        # not z3.ToInt which floors.
        _abs_floor = z3.ToInt(z3.If(self.z3_real >= 0, self.z3_real, -self.z3_real))
        _sign = z3.If(self.z3_real < 0, z3.IntVal(-1), z3.IntVal(1))
        return SymbolicValue(
            _name=self._name,
            z3_int=_abs_floor * _sign,
            is_int=Z3_FALSE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            is_path=Z3_FALSE,
        )
