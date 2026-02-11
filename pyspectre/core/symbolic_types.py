"""Extended symbolic type system for PySpectre.
This module provides a comprehensive type hierarchy that maps Python's dynamic
types to Z3's type system. Each type handles its own Z3 representation and
operations.
Type Hierarchy:
    SymbolicType (abstract base)
    ├── SymbolicPrimitive (abstract)
    │   ├── SymbolicInt        # Z3 Int
    │   ├── SymbolicBool       # Z3 Bool
    │   ├── SymbolicFloat      # Z3 Real
    │   ├── SymbolicNoneType   # Singleton
    │   └── SymbolicString     # Z3 String
    └── SymbolicCollection (abstract)
        ├── SymbolicTuple      # Fixed-length, heterogeneous
        ├── SymbolicList       # Variable-length, homogeneous
        ├── SymbolicDict       # Key-value mapping
        └── SymbolicSet        # Unordered, unique elements
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any
import z3


class TypeTag(Enum):
    """Type discriminators for runtime type checking."""

    NONE = auto()
    BOOL = auto()
    INT = auto()
    FLOAT = auto()
    STRING = auto()
    BYTES = auto()
    TUPLE = auto()
    LIST = auto()
    DICT = auto()
    SET = auto()
    OBJECT = auto()
    FUNCTION = auto()
    UNKNOWN = auto()


_type_counters: dict[str, int] = {}


def fresh_name(prefix: str) -> str:
    """Generate a unique name for a symbolic variable."""
    count = _type_counters.get(prefix, 0)
    _type_counters[prefix] = count + 1
    return f"{prefix}_{count}"


def reset_counters() -> None:
    """Reset name counters (for testing)."""
    global _type_counters
    _type_counters = {}


class SymbolicType(ABC):
    """Abstract base class for all symbolic types.
    Every symbolic type must:
    1. Have a type tag for runtime dispatch
    2. Convert to a Z3 expression
    3. Define truthiness semantics
    4. Support equality comparison
    """

    @property
    @abstractmethod
    def type_tag(self) -> TypeTag:
        """Get the type discriminator."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name for debugging."""

    @abstractmethod
    def to_z3(self) -> z3.ExprRef:
        """Convert to primary Z3 expression."""

    @abstractmethod
    def is_truthy(self) -> z3.BoolRef:
        """Z3 expression for when this value is truthy."""

    @abstractmethod
    def is_falsy(self) -> z3.BoolRef:
        """Z3 expression for when this value is falsy."""

    @abstractmethod
    def symbolic_eq(self, other: SymbolicType) -> z3.BoolRef:
        """Z3 equality expression."""

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.name})"


@dataclass
class SymbolicNoneType(SymbolicType):
    """Symbolic representation of Python None.
    None is a singleton - all None values are equal.
    Always falsy.
    """

    _name: str = field(default_factory=lambda: "None")

    @property
    def type_tag(self) -> TypeTag:
        return TypeTag.NONE

    @property
    def name(self) -> str:
        return self._name

    def to_z3(self) -> z3.ExprRef:
        return z3.IntVal(0)

    def is_truthy(self) -> z3.BoolRef:
        return z3.BoolVal(False)

    def is_falsy(self) -> z3.BoolRef:
        return z3.BoolVal(True)

    def symbolic_eq(self, other: SymbolicType) -> z3.BoolRef:
        return z3.BoolVal(isinstance(other, SymbolicNoneType))


SYMBOLIC_NONE = SymbolicNoneType()


@dataclass
class SymbolicBool(SymbolicType):
    """Symbolic boolean value.
    Uses Z3 Bool sort directly.
    """

    z3_bool: z3.BoolRef
    _name: str = field(default="")

    def __post_init__(self):
        if not self._name:
            self._name = fresh_name("bool")

    @property
    def type_tag(self) -> TypeTag:
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


@dataclass
class SymbolicInt(SymbolicType):
    """Symbolic integer value.
    Uses Z3 Int sort. Supports full integer arithmetic.
    """

    z3_int: z3.ArithRef
    _name: str = field(default="")

    def __post_init__(self):
        if not self._name:
            self._name = fresh_name("int")

    @property
    def type_tag(self) -> TypeTag:
        return TypeTag.INT

    @property
    def name(self) -> str:
        return self._name

    def to_z3(self) -> z3.ExprRef:
        return self.z3_int

    def is_truthy(self) -> z3.BoolRef:
        return self.z3_int != 0

    def is_falsy(self) -> z3.BoolRef:
        return self.z3_int == 0

    def symbolic_eq(self, other: SymbolicType) -> z3.BoolRef:
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
        return SymbolicInt(self.z3_int % other.z3_int)

    def __floordiv__(self, other: SymbolicInt) -> SymbolicInt:
        return SymbolicInt(self.z3_int / other.z3_int)

    def __truediv__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicFloat:
        if isinstance(other, SymbolicFloat):
            return SymbolicFloat(z3.ToReal(self.z3_int) / other.z3_real)
        return SymbolicFloat(z3.ToReal(self.z3_int) / z3.ToReal(other.z3_int))

    def __pow__(self, other: SymbolicInt) -> SymbolicInt:
        result_name = fresh_name(f"pow_{self._name}")
        return SymbolicInt(z3.Int(result_name), result_name)

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
        result_name = fresh_name(f"and_{self._name}")
        return SymbolicInt(z3.Int(result_name), result_name)

    def __or__(self, other: SymbolicInt) -> SymbolicInt:
        result_name = fresh_name(f"or_{self._name}")
        return SymbolicInt(z3.Int(result_name), result_name)

    def __xor__(self, other: SymbolicInt) -> SymbolicInt:
        result_name = fresh_name(f"xor_{self._name}")
        return SymbolicInt(z3.Int(result_name), result_name)

    def __invert__(self) -> SymbolicInt:
        result_name = fresh_name(f"inv_{self._name}")
        return SymbolicInt(z3.Int(result_name), result_name)

    def __lshift__(self, other: SymbolicInt) -> SymbolicInt:
        result_name = fresh_name(f"lshift_{self._name}")
        return SymbolicInt(z3.Int(result_name), result_name)

    def __rshift__(self, other: SymbolicInt) -> SymbolicInt:
        result_name = fresh_name(f"rshift_{self._name}")
        return SymbolicInt(z3.Int(result_name), result_name)

    @staticmethod
    def symbolic(name: str | None = None) -> SymbolicInt:
        """Create a fresh symbolic integer."""
        name = name or fresh_name("int")
        return SymbolicInt(z3.Int(name), name)

    @staticmethod
    def concrete(value: int) -> SymbolicInt:
        """Create a concrete integer."""
        return SymbolicInt(z3.IntVal(value), str(value))


@dataclass
class SymbolicFloat(SymbolicType):
    """Symbolic floating-point value.
    Uses Z3 Real sort for exact rational arithmetic.
    Note: This doesn't model IEEE 754 floating-point exactly.
    """

    z3_real: z3.ArithRef
    _name: str = field(default="")

    def __post_init__(self):
        if not self._name:
            self._name = fresh_name("float")

    @property
    def type_tag(self) -> TypeTag:
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
            return SymbolicFloat(self.z3_real / z3.ToReal(other.z3_int))
        return SymbolicFloat(self.z3_real / other.z3_real)

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
        """Convert to integer (truncate toward zero)."""
        return SymbolicInt(z3.ToInt(self.z3_real))

    @staticmethod
    def symbolic(name: str | None = None) -> SymbolicFloat:
        """Create a fresh symbolic float."""
        name = name or fresh_name("float")
        return SymbolicFloat(z3.Real(name), name)

    @staticmethod
    def concrete(value: float) -> SymbolicFloat:
        """Create a concrete float."""
        return SymbolicFloat(z3.RealVal(value), str(value))


@dataclass
class SymbolicString(SymbolicType):
    """Symbolic string value.
    Uses Z3's String theory for precise string reasoning.
    """

    z3_str: z3.SeqRef
    _name: str = field(default="")

    def __post_init__(self):
        if not self._name:
            self._name = fresh_name("str")

    @property
    def type_tag(self) -> TypeTag:
        return TypeTag.STRING

    @property
    def name(self) -> str:
        return self._name

    def to_z3(self) -> z3.ExprRef:
        return self.z3_str

    def is_truthy(self) -> z3.BoolRef:
        return z3.Length(self.z3_str) > 0

    def is_falsy(self) -> z3.BoolRef:
        return z3.Length(self.z3_str) == 0

    def symbolic_eq(self, other: SymbolicType) -> z3.BoolRef:
        if isinstance(other, SymbolicString):
            return self.z3_str == other.z3_str
        return z3.BoolVal(False)

    def length(self) -> SymbolicInt:
        """Return symbolic length."""
        return SymbolicInt(z3.Length(self.z3_str))

    def __add__(self, other: SymbolicString) -> SymbolicString:
        """String concatenation."""
        return SymbolicString(z3.Concat(self.z3_str, other.z3_str))

    def __mul__(self, n: SymbolicInt) -> SymbolicString:
        """String repetition (limited support)."""
        result_name = fresh_name(f"strmul_{self._name}")
        return SymbolicString(z3.String(result_name), result_name)

    def __getitem__(self, index: SymbolicInt) -> SymbolicString:
        """Character access."""
        return SymbolicString(z3.SubString(self.z3_str, index.z3_int, 1))

    def contains(self, other: SymbolicString) -> SymbolicBool:
        """Substring check."""
        return SymbolicBool(z3.Contains(self.z3_str, other.z3_str))

    def startswith(self, prefix: SymbolicString) -> SymbolicBool:
        """Check if string starts with prefix."""
        return SymbolicBool(z3.PrefixOf(prefix.z3_str, self.z3_str))

    def endswith(self, suffix: SymbolicString) -> SymbolicBool:
        """Check if string ends with suffix."""
        return SymbolicBool(z3.SuffixOf(suffix.z3_str, self.z3_str))

    def find(self, sub: SymbolicString) -> SymbolicInt:
        """Find index of substring (-1 if not found)."""
        return SymbolicInt(z3.IndexOf(self.z3_str, sub.z3_str, 0))

    def slice(self, start: SymbolicInt, length: SymbolicInt) -> SymbolicString:
        """Get substring."""
        return SymbolicString(z3.SubString(self.z3_str, start.z3_int, length.z3_int))

    def replace(self, old: SymbolicString, new: SymbolicString) -> SymbolicString:
        """Replace first occurrence."""
        return SymbolicString(z3.Replace(self.z3_str, old.z3_str, new.z3_str))

    def __lt__(self, other: SymbolicString) -> SymbolicBool:
        """Lexicographic comparison."""
        return SymbolicBool(self.z3_str < other.z3_str)

    def __le__(self, other: SymbolicString) -> SymbolicBool:
        return SymbolicBool(self.z3_str <= other.z3_str)

    def __gt__(self, other: SymbolicString) -> SymbolicBool:
        return SymbolicBool(self.z3_str > other.z3_str)

    def __ge__(self, other: SymbolicString) -> SymbolicBool:
        return SymbolicBool(self.z3_str >= other.z3_str)

    def __eq__(self, other: object) -> SymbolicBool:
        if isinstance(other, SymbolicString):
            return SymbolicBool(self.z3_str == other.z3_str)
        return SymbolicBool.concrete(False)

    def __ne__(self, other: object) -> SymbolicBool:
        eq = self.__eq__(other)
        return SymbolicBool(z3.Not(eq.z3_bool))

    @staticmethod
    def symbolic(name: str | None = None) -> SymbolicString:
        """Create a fresh symbolic string."""
        name = name or fresh_name("str")
        return SymbolicString(z3.String(name), name)

    @staticmethod
    def concrete(value: str) -> SymbolicString:
        """Create a concrete string."""
        return SymbolicString(z3.StringVal(value), repr(value))


@dataclass
class SymbolicBytes(SymbolicType):
    """Symbolic bytes value.
    Uses Z3's Sequence theory with bitvectors for byte-level operations.
    """

    z3_bytes: z3.SeqRef
    _name: str = field(default="")

    def __post_init__(self):
        if not self._name:
            self._name = fresh_name("bytes")

    @property
    def type_tag(self) -> TypeTag:
        return TypeTag.BYTES

    @property
    def name(self) -> str:
        return self._name

    def to_z3(self) -> z3.ExprRef:
        return self.z3_bytes

    def is_truthy(self) -> z3.BoolRef:
        return z3.Length(self.z3_bytes) > 0

    def is_falsy(self) -> z3.BoolRef:
        return z3.Length(self.z3_bytes) == 0

    def symbolic_eq(self, other: SymbolicType) -> z3.BoolRef:
        if isinstance(other, SymbolicBytes):
            return self.z3_bytes == other.z3_bytes
        return z3.BoolVal(False)

    def length(self) -> SymbolicInt:
        """Return symbolic length."""
        return SymbolicInt(z3.Length(self.z3_bytes))

    def __add__(self, other: SymbolicBytes) -> SymbolicBytes:
        """Bytes concatenation."""
        return SymbolicBytes(z3.Concat(self.z3_bytes, other.z3_bytes))

    @staticmethod
    def symbolic(name: str | None = None) -> SymbolicBytes:
        """Create a fresh symbolic bytes object."""
        name = name or fresh_name("bytes")
        byte_sort = z3.BitVecSort(8)
        return SymbolicBytes(z3.Const(name, z3.SeqSort(byte_sort)), name)

    @staticmethod
    def concrete(value: bytes) -> SymbolicBytes:
        """Create concrete bytes."""
        byte_sort = z3.BitVecSort(8)
        if len(value) == 0:
            return SymbolicBytes(z3.Empty(z3.SeqSort(byte_sort)), "b''")
        result = z3.Unit(z3.BitVecVal(value[0], 8))
        for b in value[1:]:
            result = z3.Concat(result, z3.Unit(z3.BitVecVal(b, 8)))
        return SymbolicBytes(result, repr(value))


@dataclass
class SymbolicTuple(SymbolicType):
    """Symbolic tuple - fixed-length, heterogeneous.
    Each element is a separate symbolic value.
    """

    elements: tuple[SymbolicType, ...]
    _name: str = field(default="")

    def __post_init__(self):
        if not self._name:
            self._name = fresh_name("tuple")

    @property
    def type_tag(self) -> TypeTag:
        return TypeTag.TUPLE

    @property
    def name(self) -> str:
        return self._name

    def to_z3(self) -> z3.ExprRef:
        if self.elements:
            return self.elements[0].to_z3()
        return z3.IntVal(0)

    def is_truthy(self) -> z3.BoolRef:
        return z3.BoolVal(len(self.elements) > 0)

    def is_falsy(self) -> z3.BoolRef:
        return z3.BoolVal(len(self.elements) == 0)

    def symbolic_eq(self, other: SymbolicType) -> z3.BoolRef:
        if isinstance(other, SymbolicTuple):
            if len(self.elements) != len(other.elements):
                return z3.BoolVal(False)
            if not self.elements:
                return z3.BoolVal(True)
            conditions = [a.symbolic_eq(b) for a, b in zip(self.elements, other.elements)]
            return z3.And(*conditions)
        return z3.BoolVal(False)

    def length(self) -> SymbolicInt:
        """Return concrete length."""
        return SymbolicInt.concrete(len(self.elements))

    def __len__(self) -> int:
        return len(self.elements)

    def __getitem__(self, index: int | SymbolicInt) -> SymbolicType:
        if isinstance(index, int):
            return self.elements[index]
        result_name = fresh_name(f"tuple_elem_{self._name}")
        return SymbolicInt(z3.Int(result_name), result_name)

    def __iter__(self) -> Iterator[SymbolicType]:
        return iter(self.elements)

    def __add__(self, other: SymbolicTuple) -> SymbolicTuple:
        """Tuple concatenation."""
        return SymbolicTuple(self.elements + other.elements)

    @staticmethod
    def from_elements(*elements: SymbolicType) -> SymbolicTuple:
        """Create a tuple from elements."""
        return SymbolicTuple(tuple(elements))

    @staticmethod
    def empty() -> SymbolicTuple:
        """Create empty tuple."""
        return SymbolicTuple(())


@dataclass
class SymbolicList(SymbolicType):
    """Symbolic list - variable-length, homogeneous.
    Uses Z3 Sequence theory for precise list operations.
    """

    z3_seq: z3.SeqRef
    element_sort: z3.SortRef
    _name: str = field(default="")

    def __post_init__(self):
        if not self._name:
            self._name = fresh_name("list")

    @property
    def type_tag(self) -> TypeTag:
        return TypeTag.LIST

    @property
    def name(self) -> str:
        return self._name

    def to_z3(self) -> z3.ExprRef:
        return self.z3_seq

    def is_truthy(self) -> z3.BoolRef:
        return z3.Length(self.z3_seq) > 0

    def is_falsy(self) -> z3.BoolRef:
        return z3.Length(self.z3_seq) == 0

    def symbolic_eq(self, other: SymbolicType) -> z3.BoolRef:
        if isinstance(other, SymbolicList):
            return self.z3_seq == other.z3_seq
        return z3.BoolVal(False)

    def length(self) -> SymbolicInt:
        """Return symbolic length."""
        return SymbolicInt(z3.Length(self.z3_seq))

    def __getitem__(self, index: SymbolicInt) -> SymbolicInt:
        """Element access (returns SymbolicInt for int lists).
        Note: Z3's sequence theory doesn't have direct element access
        like arrays. We return a fresh symbolic constrained by the sequence.
        """
        result_name = fresh_name(f"list_elem_{self._name}")
        return SymbolicInt(z3.Int(result_name), result_name)

    def __add__(self, other: SymbolicList) -> SymbolicList:
        """List concatenation."""
        return SymbolicList(z3.Concat(self.z3_seq, other.z3_seq), self.element_sort)

    def append(self, elem: SymbolicInt) -> SymbolicList:
        """Return new list with element appended."""
        return SymbolicList(z3.Concat(self.z3_seq, z3.Unit(elem.z3_int)), self.element_sort)

    def contains(self, elem: SymbolicInt) -> SymbolicBool:
        """Check if element is in list."""
        return SymbolicBool(z3.Contains(self.z3_seq, z3.Unit(elem.z3_int)))

    def slice(self, start: SymbolicInt, length: SymbolicInt) -> SymbolicList:
        """Get sublist."""
        return SymbolicList(z3.Extract(self.z3_seq, start.z3_int, length.z3_int), self.element_sort)

    @staticmethod
    def symbolic_int_list(name: str | None = None) -> SymbolicList:
        """Create a fresh symbolic list of integers."""
        name = name or fresh_name("list")
        int_seq_sort = z3.SeqSort(z3.IntSort())
        return SymbolicList(z3.Const(name, int_seq_sort), z3.IntSort(), name)

    @staticmethod
    def concrete_int_list(values: list[int]) -> SymbolicList:
        """Create a concrete list of integers."""
        int_seq_sort = z3.SeqSort(z3.IntSort())
        if not values:
            return SymbolicList(z3.Empty(int_seq_sort), z3.IntSort(), "[]")
        result = z3.Unit(z3.IntVal(values[0]))
        for v in values[1:]:
            result = z3.Concat(result, z3.Unit(z3.IntVal(v)))
        return SymbolicList(result, z3.IntSort(), str(values))


@dataclass
class SymbolicDict(SymbolicType):
    """Symbolic dictionary.
    Uses Z3 Array theory: Dict[K, V] -> Array(K, Option[V])
    """

    z3_array: z3.ArrayRef
    key_sort: z3.SortRef
    value_sort: z3.SortRef
    _name: str = field(default="")

    def __post_init__(self):
        if not self._name:
            self._name = fresh_name("dict")

    @property
    def type_tag(self) -> TypeTag:
        return TypeTag.DICT

    @property
    def name(self) -> str:
        return self._name

    def to_z3(self) -> z3.ExprRef:
        return self.z3_array

    def is_truthy(self) -> z3.BoolRef:
        return z3.Bool(fresh_name(f"dict_nonempty_{self._name}"))

    def is_falsy(self) -> z3.BoolRef:
        return z3.Not(self.is_truthy())

    def symbolic_eq(self, other: SymbolicType) -> z3.BoolRef:
        if isinstance(other, SymbolicDict):
            return self.z3_array == other.z3_array
        return z3.BoolVal(False)

    def __getitem__(self, key: SymbolicInt) -> SymbolicInt:
        """Dictionary lookup."""
        return SymbolicInt(z3.Select(self.z3_array, key.z3_int))

    def __setitem__(self, key: SymbolicInt, value: SymbolicInt) -> SymbolicDict:
        """Return new dict with updated key."""
        return SymbolicDict(
            z3.Store(self.z3_array, key.z3_int, value.z3_int), self.key_sort, self.value_sort
        )

    def get(self, key: SymbolicInt, default: SymbolicInt) -> SymbolicInt:
        """Get with default (simplified - always returns stored value)."""
        return self[key]

    @staticmethod
    def symbolic_int_dict(name: str | None = None) -> SymbolicDict:
        """Create a fresh symbolic dict with int keys and int values."""
        name = name or fresh_name("dict")
        array_sort = z3.ArraySort(z3.IntSort(), z3.IntSort())
        return SymbolicDict(z3.Const(name, array_sort), z3.IntSort(), z3.IntSort(), name)


@dataclass
class SymbolicSet(SymbolicType):
    """Symbolic set.
    Uses Z3 Set theory for set operations.
    """

    z3_set: z3.ArrayRef
    element_sort: z3.SortRef
    _name: str = field(default="")

    def __post_init__(self):
        if not self._name:
            self._name = fresh_name("set")

    @property
    def type_tag(self) -> TypeTag:
        return TypeTag.SET

    @property
    def name(self) -> str:
        return self._name

    def to_z3(self) -> z3.ExprRef:
        return self.z3_set

    def is_truthy(self) -> z3.BoolRef:
        return z3.Bool(fresh_name(f"set_nonempty_{self._name}"))

    def is_falsy(self) -> z3.BoolRef:
        return z3.Not(self.is_truthy())

    def symbolic_eq(self, other: SymbolicType) -> z3.BoolRef:
        if isinstance(other, SymbolicSet):
            return self.z3_set == other.z3_set
        return z3.BoolVal(False)

    def contains(self, elem: SymbolicInt) -> SymbolicBool:
        """Check set membership."""
        return SymbolicBool(z3.IsMember(elem.z3_int, self.z3_set))

    def add(self, elem: SymbolicInt) -> SymbolicSet:
        """Return new set with element added."""
        return SymbolicSet(z3.SetAdd(self.z3_set, elem.z3_int), self.element_sort)

    def remove(self, elem: SymbolicInt) -> SymbolicSet:
        """Return new set with element removed."""
        return SymbolicSet(z3.SetDel(self.z3_set, elem.z3_int), self.element_sort)

    def union(self, other: SymbolicSet) -> SymbolicSet:
        """Set union."""
        return SymbolicSet(z3.SetUnion(self.z3_set, other.z3_set), self.element_sort)

    def intersection(self, other: SymbolicSet) -> SymbolicSet:
        """Set intersection."""
        return SymbolicSet(z3.SetIntersect(self.z3_set, other.z3_set), self.element_sort)

    def difference(self, other: SymbolicSet) -> SymbolicSet:
        """Set difference."""
        return SymbolicSet(z3.SetDifference(self.z3_set, other.z3_set), self.element_sort)

    def issubset(self, other: SymbolicSet) -> SymbolicBool:
        """Check if this is a subset of other."""
        return SymbolicBool(z3.IsSubset(self.z3_set, other.z3_set))

    @staticmethod
    def symbolic_int_set(name: str | None = None) -> SymbolicSet:
        """Create a fresh symbolic set of integers."""
        name = name or fresh_name("set")
        return SymbolicSet(z3.Const(name, z3.SetSort(z3.IntSort())), z3.IntSort(), name)

    @staticmethod
    def empty_int_set() -> SymbolicSet:
        """Create an empty int set."""
        return SymbolicSet(z3.EmptySet(z3.IntSort()), z3.IntSort(), "set()")


def coerce_to_bool(value: SymbolicType) -> SymbolicBool:
    """Convert any symbolic type to boolean."""
    if isinstance(value, SymbolicBool):
        return value
    return SymbolicBool(value.is_truthy())


def coerce_to_int(value: SymbolicType) -> SymbolicInt:
    """Convert symbolic type to int where possible."""
    if isinstance(value, SymbolicInt):
        return value
    elif isinstance(value, SymbolicBool):
        return SymbolicInt(z3.If(value.z3_bool, z3.IntVal(1), z3.IntVal(0)))
    elif isinstance(value, SymbolicFloat):
        return value.to_int()
    else:
        return SymbolicInt.symbolic(f"int_{value.name}")


def coerce_to_float(value: SymbolicType) -> SymbolicFloat:
    """Convert symbolic type to float where possible."""
    if isinstance(value, SymbolicFloat):
        return value
    elif isinstance(value, SymbolicInt):
        return SymbolicFloat(z3.ToReal(value.z3_int))
    elif isinstance(value, SymbolicBool):
        return SymbolicFloat(z3.If(value.z3_bool, z3.RealVal(1), z3.RealVal(0)))
    else:
        return SymbolicFloat.symbolic(f"float_{value.name}")


def coerce_to_string(value: SymbolicType) -> SymbolicString:
    """Convert symbolic type to string where possible."""
    if isinstance(value, SymbolicString):
        return value
    elif isinstance(value, SymbolicInt):
        return SymbolicString(z3.IntToStr(value.z3_int))
    else:
        return SymbolicString.symbolic(f"str_{value.name}")


def symbolic_from_python(value: Any) -> SymbolicType:
    """Create a symbolic value from a Python value."""
    if value is None:
        return SYMBOLIC_NONE
    elif isinstance(value, bool):
        return SymbolicBool.concrete(value)
    elif isinstance(value, int):
        return SymbolicInt.concrete(value)
    elif isinstance(value, float):
        return SymbolicFloat.concrete(value)
    elif isinstance(value, str):
        return SymbolicString.concrete(value)
    elif isinstance(value, bytes):
        return SymbolicBytes.concrete(value)
    elif isinstance(value, tuple):
        elements = tuple(symbolic_from_python(e) for e in value)
        return SymbolicTuple(elements)
    elif isinstance(value, list):
        if not value:
            return SymbolicList.concrete_int_list([])
        if all(isinstance(e, int) for e in value):
            return SymbolicList.concrete_int_list(value)
        return SymbolicList.symbolic_int_list()
    elif isinstance(value, dict):
        return SymbolicDict.symbolic_int_dict()
    elif isinstance(value, set):
        return SymbolicSet.symbolic_int_set()
    else:
        return SymbolicInt.symbolic(f"unknown_{type(value).__name__}")


def symbolic_for_type(type_hint: type, name: str | None = None) -> SymbolicType:
    """Create a fresh symbolic value for a type hint."""
    if type_hint is type(None):
        return SYMBOLIC_NONE
    elif type_hint is bool:
        return SymbolicBool.symbolic(name)
    elif type_hint is int:
        return SymbolicInt.symbolic(name)
    elif type_hint is float:
        return SymbolicFloat.symbolic(name)
    elif type_hint is str:
        return SymbolicString.symbolic(name)
    elif type_hint is bytes:
        return SymbolicBytes.symbolic(name)
    elif type_hint is list:
        return SymbolicList.symbolic_int_list(name)
    elif type_hint is dict:
        return SymbolicDict.symbolic_int_dict(name)
    elif type_hint is set:
        return SymbolicSet.symbolic_int_set(name)
    else:
        return SymbolicInt.symbolic(name)


def is_numeric(value: SymbolicType) -> bool:
    """Check if value is numeric (int or float)."""
    return isinstance(value, (SymbolicInt, SymbolicFloat))


def is_sequence(value: SymbolicType) -> bool:
    """Check if value is a sequence type."""
    return isinstance(value, (SymbolicString, SymbolicBytes, SymbolicTuple, SymbolicList))


def is_collection(value: SymbolicType) -> bool:
    """Check if value is any collection type."""
    return isinstance(value, (SymbolicTuple, SymbolicList, SymbolicDict, SymbolicSet))


def get_common_type(a: SymbolicType, b: SymbolicType) -> TypeTag:
    """Get the common type for binary operations."""
    if isinstance(a, SymbolicFloat) or isinstance(b, SymbolicFloat):
        return TypeTag.FLOAT
    if isinstance(a, SymbolicInt) or isinstance(b, SymbolicInt):
        return TypeTag.INT
    if isinstance(a, SymbolicBool) and isinstance(b, SymbolicBool):
        return TypeTag.BOOL
    return TypeTag.UNKNOWN
