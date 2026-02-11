"""Core symbolic types for PySpectre.
This module defines the symbolic type system that bridges Python's dynamic
typing with Z3's static typing. Each Python value is represented as a
union of possible Z3 types with type discriminators.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Union, Any
import z3

if TYPE_CHECKING:
    pass
_sym_counter = 0


def _fresh_name(prefix: str) -> str:
    """Generate a unique symbolic variable name."""
    global _sym_counter
    _sym_counter += 1
    return f"{prefix}_{_sym_counter}"


class SymbolicType(ABC):
    """Abstract base class for all symbolic types."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name for debugging."""

    @abstractmethod
    def to_z3(self) -> z3.ExprRef:
        """Convert to primary Z3 expression."""

    @abstractmethod
    def could_be_truthy(self) -> z3.BoolRef:
        """Z3 expression for when this value is truthy."""

    @abstractmethod
    def could_be_falsy(self) -> z3.BoolRef:
        """Z3 expression for when this value is falsy."""


@dataclass
class SymbolicNone(SymbolicType):
    """Represents Python None."""

    _name: str = field(default_factory=lambda: _fresh_name("none"))

    @property
    def name(self) -> str:
        return "None"

    def to_z3(self) -> z3.ExprRef:
        return z3.BoolVal(False)

    def could_be_truthy(self) -> z3.BoolRef:
        return z3.BoolVal(False)

    def could_be_falsy(self) -> z3.BoolRef:
        return z3.BoolVal(True)

    def conditional_merge(self, other: AnySymbolic, condition: z3.BoolRef) -> AnySymbolic:
        """Merge with another value based on a condition."""
        if isinstance(other, SymbolicNone):
            return self
        if hasattr(other, "address"):
            return other.conditional_merge(self, z3.Not(condition))
        fresh, _ = SymbolicValue.symbolic(_fresh_name("merge_none"))
        return SymbolicValue(
            _name=f"If({condition}, None, {other.name})",
            z3_int=z3.If(condition, z3.IntVal(0), other.to_z3()),
            is_int=z3.If(condition, z3.BoolVal(False), getattr(other, "is_int", z3.BoolVal(False))),
            z3_bool=z3.If(
                condition, z3.BoolVal(False), getattr(other, "z3_bool", z3.BoolVal(False))
            ),
            is_bool=z3.If(
                condition, z3.BoolVal(False), getattr(other, "is_bool", z3.BoolVal(False))
            ),
            taint_labels=(
                (getattr(other, "taint_labels", set()) or frozenset())
                if getattr(other, "taint_labels", None)
                else None
            ),
        )

    def __repr__(self) -> str:
        return "SymbolicNone()"


@dataclass
class SymbolicValue(SymbolicType):
    """Union type representing an integer or boolean symbolic value.
    Attributes:
        _name: Debugging name
        z3_int: Z3 integer expression
        is_int: Z3 boolean - True if this is an integer
        z3_bool: Z3 boolean expression
        is_bool: Z3 boolean - True if this is a boolean
        is_none: Z3 boolean - True if this could be None
    """

    _name: str
    z3_int: z3.ArithRef
    is_int: z3.BoolRef
    z3_bool: z3.BoolRef
    is_bool: z3.BoolRef
    is_path: z3.BoolRef = field(default_factory=lambda: z3.BoolVal(False))
    is_none: z3.BoolRef = field(default_factory=lambda: z3.BoolVal(False))
    taint_labels: set[str] | frozenset[str] | None = field(default=None, compare=False)

    @property
    def name(self) -> str:
        return self._name

    def to_z3(self) -> z3.ExprRef:
        return self.z3_int

    def could_be_truthy(self) -> z3.BoolRef:
        return z3.Or(
            z3.And(self.is_bool, self.z3_bool),
            z3.And(self.is_int, self.z3_int != 0),
            self.is_path,
        )

    def could_be_falsy(self) -> z3.BoolRef:
        return z3.Or(
            z3.And(self.is_bool, z3.Not(self.z3_bool)),
            z3.And(self.is_int, self.z3_int == 0),
            z3.Not(self.is_path),
        )

    def with_taint(self, label: str | set[str] | frozenset[str]) -> SymbolicValue:
        """Return a copy with added taint."""
        import dataclasses

        new_labels = set(self.taint_labels or set())
        if isinstance(label, str):
            new_labels.add(label)
        else:
            new_labels.update(label)
        return dataclasses.replace(self, taint_labels=frozenset(new_labels))

    def conditional_merge(self, other: AnySymbolic, condition: z3.BoolRef) -> SymbolicValue:
        """Merge with another value based on a condition: If(condition, self, other)."""
        if isinstance(other, SymbolicNone):
            return other.conditional_merge(self, z3.Not(condition))
        if not isinstance(other, SymbolicValue):
            if hasattr(other, "to_z3"):
                pass
            else:
                other = SymbolicValue.from_const(other)
        new_int = z3.If(condition, self.z3_int, other.z3_int)
        new_is_int = z3.If(condition, self.is_int, other.is_int)
        new_bool = z3.If(condition, self.z3_bool, other.z3_bool)
        new_is_bool = z3.If(condition, self.is_bool, other.is_bool)
        new_is_path = z3.If(condition, self.is_path, other.is_path)
        new_is_none = z3.If(condition, self.is_none, getattr(other, "is_none", z3.BoolVal(False)))
        return SymbolicValue(
            _name=f"If({condition}, {self._name}, {other.name})",
            z3_int=new_int,
            is_int=new_is_int,
            z3_bool=new_bool,
            is_bool=new_is_bool,
            is_path=new_is_path,
            is_none=new_is_none,
            taint_labels=(self.taint_labels or frozenset()) | (other.taint_labels or frozenset()),
        )

    @staticmethod
    def symbolic(name: str) -> tuple[SymbolicValue, z3.BoolRef]:
        """Create a fresh symbolic value with type constraint."""
        z3_int = z3.Int(f"{name}_int")
        z3_bool = z3.Bool(f"{name}_bool")
        is_int = z3.Bool(f"{name}_is_int")
        is_bool = z3.Bool(f"{name}_is_bool")
        is_path = z3.Bool(f"{name}_is_path")
        type_constraint = z3.And(
            z3.Or(is_int, is_bool, is_path),
            z3.Not(z3.And(is_int, is_bool)),
            z3.Not(z3.And(is_int, is_path)),
            z3.Not(z3.And(is_bool, is_path)),
        )
        return SymbolicValue(name, z3_int, is_int, z3_bool, is_bool, is_path), type_constraint

    @staticmethod
    def from_const(value: object) -> SymbolicValue:
        """Create a concrete symbolic value from a Python constant."""
        if value is None:
            return SymbolicValue(
                _name="None",
                z3_int=z3.IntVal(0),
                is_int=z3.BoolVal(False),
                z3_bool=z3.BoolVal(False),
                is_bool=z3.BoolVal(False),
                is_path=z3.BoolVal(False),
                is_none=z3.BoolVal(True),
            )
        if isinstance(value, bool):
            return SymbolicValue(
                _name=str(value),
                z3_int=z3.IntVal(1 if value else 0),
                is_int=z3.BoolVal(False),
                z3_bool=z3.BoolVal(value),
                is_bool=z3.BoolVal(True),
                is_path=z3.BoolVal(False),
            )
        if isinstance(value, int):
            return SymbolicValue(
                _name=str(value),
                z3_int=z3.IntVal(value),
                is_int=z3.BoolVal(True),
                z3_bool=z3.BoolVal(False),
                is_bool=z3.BoolVal(False),
                is_path=z3.BoolVal(False),
            )
        return SymbolicValue(
            _name=str(value),
            z3_int=z3.IntVal(0),
            is_int=z3.BoolVal(False),
            z3_bool=z3.BoolVal(False),
            is_bool=z3.BoolVal(False),
            is_path=z3.BoolVal(False),
        )

    @staticmethod
    def from_z3(expr: z3.ExprRef, name: str | None = None) -> SymbolicValue:
        """Create a SymbolicValue from a Z3 expression.

        Args:
            expr: The Z3 expression (ArithRef or BoolRef)
            name: Optional name for debugging

        Returns:
            A SymbolicValue wrapping the Z3 expression
        """
        if name is None:
            name = str(expr)
        if isinstance(expr, z3.BoolRef):
            return SymbolicValue(
                _name=name,
                z3_int=z3.If(expr, z3.IntVal(1), z3.IntVal(0)),
                is_int=z3.BoolVal(False),
                z3_bool=expr,
                is_bool=z3.BoolVal(True),
                is_path=z3.BoolVal(False),
            )
        elif isinstance(expr, z3.ArithRef):
            return SymbolicValue(
                _name=name,
                z3_int=expr,
                is_int=z3.BoolVal(True),
                z3_bool=z3.BoolVal(False),
                is_bool=z3.BoolVal(False),
                is_path=z3.BoolVal(False),
            )
        else:
            return SymbolicValue(
                _name=name,
                z3_int=z3.IntVal(0),
                is_int=z3.BoolVal(False),
                z3_bool=z3.BoolVal(False),
                is_bool=z3.BoolVal(False),
                is_path=z3.BoolVal(False),
            )

    @staticmethod
    def symbolic_path(name: str) -> tuple[SymbolicValue, z3.BoolRef]:
        """Create a fresh symbolic path."""
        val, constraint = SymbolicValue.symbolic(name)
        path_constraint = z3.And(constraint, val.is_path)
        return val, path_constraint

    def __add__(self, other: SymbolicValue) -> SymbolicValue:
        return SymbolicValue(
            _name=f"({self._name}+{other._name})",
            z3_int=self.z3_int + other.z3_int,
            is_int=z3.And(self.is_int, other.is_int),
            z3_bool=z3.BoolVal(False),
            is_bool=z3.BoolVal(False),
            taint_labels=(self.taint_labels or frozenset()) | (other.taint_labels or frozenset()),
        )

    def __sub__(self, other: SymbolicValue) -> SymbolicValue:
        return SymbolicValue(
            _name=f"({self._name}-{other._name})",
            z3_int=self.z3_int - other.z3_int,
            is_int=z3.And(self.is_int, other.is_int),
            z3_bool=z3.BoolVal(False),
            is_bool=z3.BoolVal(False),
            taint_labels=(self.taint_labels or frozenset()) | (other.taint_labels or frozenset()),
        )

    def __mul__(self, other: SymbolicValue) -> SymbolicValue:
        return SymbolicValue(
            _name=f"({self._name}*{other._name})",
            z3_int=self.z3_int * other.z3_int,
            is_int=z3.And(self.is_int, other.is_int),
            z3_bool=z3.BoolVal(False),
            is_bool=z3.BoolVal(False),
            taint_labels=(self.taint_labels or frozenset()) | (other.taint_labels or frozenset()),
        )

    def __neg__(self) -> SymbolicValue:
        return SymbolicValue(
            _name=f"(-{self._name})",
            z3_int=-self.z3_int,
            is_int=self.is_int,
            z3_bool=z3.BoolVal(False),
            is_bool=z3.BoolVal(False),
            taint_labels=self.taint_labels,
        )

    def __mod__(self, other: SymbolicValue) -> SymbolicValue:
        return SymbolicValue(
            _name=f"({self._name}%{other._name})",
            z3_int=self.z3_int % other.z3_int,
            is_int=z3.And(self.is_int, other.is_int),
            z3_bool=z3.BoolVal(False),
            is_bool=z3.BoolVal(False),
            taint_labels=(self.taint_labels or frozenset()) | (other.taint_labels or frozenset()),
        )

    def __floordiv__(self, other: SymbolicValue) -> SymbolicValue:
        return SymbolicValue(
            _name=f"({self._name}//{other._name})",
            z3_int=self.z3_int / other.z3_int,
            is_int=z3.And(self.is_int, other.is_int),
            z3_bool=z3.BoolVal(False),
            is_bool=z3.BoolVal(False),
            is_path=z3.BoolVal(False),
            taint_labels=(self.taint_labels or frozenset()) | (other.taint_labels or frozenset()),
        )

    def __truediv__(self, other: SymbolicValue) -> SymbolicValue:
        is_path = self.is_path
        return SymbolicValue(
            _name=f"({self._name}/{other._name})",
            z3_int=self.z3_int / other.z3_int,
            is_int=z3.And(self.is_int, other.is_int),
            z3_bool=z3.BoolVal(False),
            is_bool=z3.BoolVal(False),
            is_path=is_path,
            taint_labels=(self.taint_labels or frozenset()) | (other.taint_labels or frozenset()),
        )

    def __pow__(self, other: SymbolicValue) -> SymbolicValue:
        fresh, _ = SymbolicValue.symbolic(f"{self._name}**{other._name}")
        import dataclasses

        taint = (self.taint_labels or frozenset()) | (other.taint_labels or frozenset())
        if taint:
            fresh = dataclasses.replace(fresh, taint_labels=taint)
        return fresh

    def __eq__(self, other: object) -> SymbolicValue:
        if not isinstance(other, SymbolicValue):
            other = SymbolicValue.from_const(other)
        int_eq = z3.And(self.is_int, other.is_int, self.z3_int == other.z3_int)
        bool_eq = z3.And(self.is_bool, other.is_bool, self.z3_bool == other.z3_bool)
        result_bool = z3.Or(int_eq, bool_eq)
        return SymbolicValue(
            _name=f"({self._name}=={getattr(other, '_name', str(other))})",
            z3_int=z3.IntVal(0),
            is_int=z3.BoolVal(False),
            z3_bool=result_bool,
            is_bool=z3.BoolVal(True),
            taint_labels=(self.taint_labels or frozenset()) | (other.taint_labels or frozenset()),
        )

    def __ne__(self, other: object) -> SymbolicValue:
        if not isinstance(other, SymbolicValue):
            other = SymbolicValue.from_const(other)
        eq = self.__eq__(other)
        return SymbolicValue(
            _name=f"({self._name}!={getattr(other, '_name', str(other))})",
            z3_int=z3.IntVal(0),
            is_int=z3.BoolVal(False),
            z3_bool=z3.Not(eq.z3_bool),
            is_bool=z3.BoolVal(True),
            taint_labels=(self.taint_labels or frozenset()) | (other.taint_labels or frozenset()),
        )

    def __lt__(self, other: Any) -> SymbolicValue:
        if not isinstance(other, SymbolicValue):
            other = SymbolicValue.from_const(other)
        return SymbolicValue(
            _name=f"({self._name}<{other.name})",
            z3_int=z3.IntVal(0),
            is_int=z3.BoolVal(False),
            z3_bool=self.z3_int < other.z3_int,
            is_bool=z3.And(self.is_int, other.is_int),
            taint_labels=(self.taint_labels or frozenset()) | (other.taint_labels or frozenset()),
        )

    def __le__(self, other: Any) -> SymbolicValue:
        if not isinstance(other, SymbolicValue):
            other = SymbolicValue.from_const(other)
        return SymbolicValue(
            _name=f"({self._name}<={other.name})",
            z3_int=z3.IntVal(0),
            is_int=z3.BoolVal(False),
            z3_bool=self.z3_int <= other.z3_int,
            is_bool=z3.And(self.is_int, other.is_int),
            taint_labels=(self.taint_labels or frozenset()) | (other.taint_labels or frozenset()),
        )

    def __gt__(self, other: Any) -> SymbolicValue:
        if not isinstance(other, SymbolicValue):
            other = SymbolicValue.from_const(other)
        return SymbolicValue(
            _name=f"({self._name}>{other.name})",
            z3_int=z3.IntVal(0),
            is_int=z3.BoolVal(False),
            z3_bool=self.z3_int > other.z3_int,
            is_bool=z3.And(self.is_int, other.is_int),
            taint_labels=(self.taint_labels or frozenset()) | (other.taint_labels or frozenset()),
        )

    def __ge__(self, other: Any) -> SymbolicValue:
        if not isinstance(other, SymbolicValue):
            other = SymbolicValue.from_const(other)
        return SymbolicValue(
            _name=f"({self._name}>={other.name})",
            z3_int=z3.IntVal(0),
            is_int=z3.BoolVal(False),
            z3_bool=self.z3_int >= other.z3_int,
            is_bool=z3.And(self.is_int, other.is_int),
            taint_labels=(self.taint_labels or frozenset()) | (other.taint_labels or frozenset()),
        )

    def __and__(self, other: SymbolicValue) -> SymbolicValue:
        return SymbolicValue(
            _name=f"({self._name}&{other._name})",
            z3_int=z3.IntVal(0),
            is_int=z3.BoolVal(False),
            z3_bool=z3.And(self.z3_bool, other.z3_bool),
            is_bool=z3.And(self.is_bool, other.is_bool),
            taint_labels=(self.taint_labels or frozenset()) | (other.taint_labels or frozenset()),
        )

    def __or__(self, other: SymbolicValue) -> SymbolicValue:
        return SymbolicValue(
            _name=f"({self._name}|{other._name})",
            z3_int=z3.IntVal(0),
            is_int=z3.BoolVal(False),
            z3_bool=z3.Or(self.z3_bool, other.z3_bool),
            is_bool=z3.And(self.is_bool, other.is_bool),
            taint_labels=(self.taint_labels or frozenset()) | (other.taint_labels or frozenset()),
        )

    def __xor__(self, other: SymbolicValue) -> SymbolicValue:
        return SymbolicValue(
            _name=f"({self._name}^{other._name})",
            z3_int=z3.IntVal(0),
            is_int=z3.BoolVal(False),
            z3_bool=z3.Xor(self.z3_bool, other.z3_bool),
            is_bool=z3.And(self.is_bool, other.is_bool),
            taint_labels=(self.taint_labels or frozenset()) | (other.taint_labels or frozenset()),
        )

    def __invert__(self) -> SymbolicValue:
        return SymbolicValue(
            _name=f"(~{self._name})",
            z3_int=z3.IntVal(0),
            is_int=z3.BoolVal(False),
            z3_bool=z3.Not(self.z3_bool),
            is_bool=self.is_bool,
            taint_labels=self.taint_labels,
        )

    def logical_not(self) -> SymbolicValue:
        """Python 'not' operator."""
        return SymbolicValue(
            _name=f"(not {self._name})",
            z3_int=z3.IntVal(0),
            is_int=z3.BoolVal(False),
            z3_bool=z3.Not(self.could_be_truthy()),
            is_bool=z3.BoolVal(True),
        )

    def __repr__(self) -> str:
        return f"SymbolicValue({self._name})"


@dataclass
class SymbolicString(SymbolicType):
    """Symbolic string using Z3 string theory.
    Attributes:
        _name: Debugging name
        z3_str: Z3 string expression
        z3_len: Z3 integer for string length
    """

    _name: str
    z3_str: z3.SeqRef
    z3_len: z3.ArithRef
    taint_labels: set[str] | frozenset[str] | None = field(default=None, compare=False)

    @property
    def name(self) -> str:
        return self._name

    def to_z3(self) -> z3.ExprRef:
        return self.z3_str

    def could_be_truthy(self) -> z3.BoolRef:
        return self.z3_len > 0

    def could_be_falsy(self) -> z3.BoolRef:
        return self.z3_len == 0

    def with_taint(self, label: str | set[str] | frozenset[str]) -> SymbolicString:
        """Return a copy with added taint."""
        import dataclasses

        new_labels = set(self.taint_labels or set())
        if isinstance(label, str):
            new_labels.add(label)
        else:
            new_labels.update(label)
        return dataclasses.replace(self, taint_labels=frozenset(new_labels))

    @staticmethod
    def symbolic(name: str) -> tuple[SymbolicString, z3.BoolRef]:
        """Create a fresh symbolic string."""
        z3_str = z3.String(f"{name}_str")
        z3_len = z3.Length(z3_str)
        constraint = z3_len >= 0
        return SymbolicString(name, z3_str, z3_len), constraint

    @staticmethod
    def from_const(value: str) -> SymbolicString:
        """Create a concrete symbolic string."""
        z3_str = z3.StringVal(value)
        z3_len = z3.IntVal(len(value))
        return SymbolicString(repr(value), z3_str, z3_len)

    def __add__(self, other: SymbolicString) -> SymbolicString:
        """String concatenation."""
        return SymbolicString(
            _name=f"({self._name}+{other._name})",
            z3_str=z3.Concat(self.z3_str, other.z3_str),
            z3_len=self.z3_len + other.z3_len,
            taint_labels=(self.taint_labels or frozenset()) | (other.taint_labels or frozenset()),
        )

    def __getitem__(self, index: SymbolicValue) -> SymbolicString:
        """String indexing - returns single character string."""
        return SymbolicString(
            _name=f"{self._name}[{index._name}]",
            z3_str=z3.SubString(self.z3_str, index.z3_int, z3.IntVal(1)),
            z3_len=z3.IntVal(1),
            taint_labels=(self.taint_labels or frozenset()) | (index.taint_labels or frozenset()),
        )

    def substring(self, start: SymbolicValue, length: SymbolicValue) -> SymbolicString:
        """Extract substring."""
        return SymbolicString(
            _name=f"{self._name}[{start._name}:{start._name}+{length._name}]",
            z3_str=z3.SubString(self.z3_str, start.z3_int, length.z3_int),
            z3_len=length.z3_int,
            taint_labels=(self.taint_labels or frozenset())
            | (start.taint_labels or frozenset())
            | (length.taint_labels or frozenset()),
        )

    def contains(self, other: SymbolicString) -> SymbolicValue:
        """Check if string contains another string."""
        result = z3.Contains(self.z3_str, other.z3_str)
        return SymbolicValue(
            _name=f"({other._name} in {self._name})",
            z3_int=z3.IntVal(0),
            is_int=z3.BoolVal(False),
            z3_bool=result,
            is_bool=z3.BoolVal(True),
            taint_labels=(self.taint_labels or frozenset()) | (other.taint_labels or frozenset()),
        )

    def index_of(self, other: SymbolicString) -> SymbolicValue:
        """Find index of substring."""
        idx = z3.IndexOf(self.z3_str, other.z3_str, z3.IntVal(0))
        return SymbolicValue(
            _name=f"{self._name}.index({other._name})",
            z3_int=idx,
            is_int=z3.BoolVal(True),
            z3_bool=z3.BoolVal(False),
            is_bool=z3.BoolVal(False),
            taint_labels=(self.taint_labels or frozenset()) | (other.taint_labels or frozenset()),
        )

    def length(self) -> SymbolicValue:
        """Get string length."""
        return SymbolicValue(
            _name=f"len({self._name})",
            z3_int=self.z3_len,
            is_int=z3.BoolVal(True),
            z3_bool=z3.BoolVal(False),
            is_bool=z3.BoolVal(False),
            taint_labels=self.taint_labels,
        )

    def __eq__(self, other: object) -> SymbolicValue:
        if not isinstance(other, SymbolicString):
            return SymbolicValue.from_const(False)
        return SymbolicValue(
            _name=f"({self._name}=={other._name})",
            z3_int=z3.IntVal(0),
            is_int=z3.BoolVal(False),
            z3_bool=self.z3_str == other.z3_str,
            is_bool=z3.BoolVal(True),
            taint_labels=(self.taint_labels or frozenset()) | (other.taint_labels or frozenset()),
        )

    def conditional_merge(self, other: AnySymbolic, condition: z3.BoolRef) -> SymbolicString:
        """Merge with another string based on condition."""
        if not isinstance(other, SymbolicString):
            from pyspectre.core.types import SymbolicValue

            return SymbolicValue.from_const(0)
        new_str = z3.If(condition, self.z3_str, other.z3_str)
        new_len = z3.If(condition, self.z3_len, other.z3_len)
        return SymbolicString(
            _name=f"If({condition}, {self._name}, {other.name})",
            z3_str=new_str,
            z3_len=new_len,
            taint_labels=(self.taint_labels or frozenset()) | (other.taint_labels or frozenset()),
        )

    def __repr__(self) -> str:
        return f"SymbolicString({self._name})"


@dataclass
class SymbolicList(SymbolicType):
    """Symbolic list using Z3 arrays and explicit length tracking.
    Attributes:
        _name: Debugging name
        z3_array: Z3 array from Int to symbolic elements
        z3_len: Z3 integer for list length
        element_type: String describing the element type
    """

    _name: str
    z3_array: z3.ArrayRef
    z3_len: z3.ArithRef
    element_type: str = "int"
    taint_labels: set[str] | frozenset[str] | None = field(default=None, compare=False)

    @property
    def name(self) -> str:
        return self._name

    def to_z3(self) -> z3.ExprRef:
        return self.z3_array

    def could_be_truthy(self) -> z3.BoolRef:
        return self.z3_len > 0

    def could_be_falsy(self) -> z3.BoolRef:
        return self.z3_len == 0

    def with_taint(self, label: str | set[str] | frozenset[str]) -> SymbolicList:
        """Return a copy with added taint."""
        import dataclasses

        new_labels = set(self.taint_labels or set())
        if isinstance(label, str):
            new_labels.add(label)
        else:
            new_labels.update(label)
        return dataclasses.replace(self, taint_labels=frozenset(new_labels))

    @staticmethod
    def symbolic(name: str, element_type: str = "int") -> tuple[SymbolicList, z3.BoolRef]:
        """Create a fresh symbolic list."""
        z3_array = z3.Array(f"{name}_arr", z3.IntSort(), z3.IntSort())
        z3_len = z3.Int(f"{name}_len")
        constraint = z3_len >= 0
        return SymbolicList(name, z3_array, z3_len, element_type), constraint

    @staticmethod
    def from_const(values: list[int]) -> SymbolicList:
        """Create a concrete symbolic list from integers."""
        name = _fresh_name("list")
        z3_array = z3.Array(f"{name}_arr", z3.IntSort(), z3.IntSort())
        for i, v in enumerate(values):
            z3_array = z3.Store(z3_array, i, v)
        z3_len = z3.IntVal(len(values))
        return SymbolicList(str(values), z3_array, z3_len)

    def __getitem__(self, index: SymbolicValue) -> SymbolicValue:
        """List indexing."""
        elem = z3.Select(self.z3_array, index.z3_int)
        return SymbolicValue(
            _name=f"{self._name}[{index._name}]",
            z3_int=elem,
            is_int=z3.BoolVal(True),
            z3_bool=z3.BoolVal(False),
            is_bool=z3.BoolVal(False),
            taint_labels=(self.taint_labels or frozenset()) | (index.taint_labels or frozenset()),
        )

    def __setitem__(self, index: SymbolicValue, value: SymbolicValue) -> SymbolicList:
        """List assignment - returns new list (immutable semantics)."""
        new_array = z3.Store(self.z3_array, index.z3_int, value.z3_int)
        return SymbolicList(
            _name=f"{self._name}[{index._name}]={value._name}",
            z3_array=new_array,
            z3_len=self.z3_len,
            element_type=self.element_type,
            taint_labels=(self.taint_labels or frozenset())
            | (index.taint_labels or frozenset())
            | (value.taint_labels or frozenset()),
        )

    def append(self, value: SymbolicValue) -> SymbolicList:
        """Append element - returns new list."""
        new_array = z3.Store(self.z3_array, self.z3_len, value.z3_int)
        return SymbolicList(
            _name=f"{self._name}.append({value._name})",
            z3_array=new_array,
            z3_len=self.z3_len + 1,
            element_type=self.element_type,
            taint_labels=(self.taint_labels or frozenset()) | (value.taint_labels or frozenset()),
        )

    def length(self) -> SymbolicValue:
        """Get list length."""
        return SymbolicValue(
            _name=f"len({self._name})",
            z3_int=self.z3_len,
            is_int=z3.BoolVal(True),
            z3_bool=z3.BoolVal(False),
            is_bool=z3.BoolVal(False),
        )

    def in_bounds(self, index: SymbolicValue) -> z3.BoolRef:
        """Check if index is valid."""
        return z3.And(index.z3_int >= 0, index.z3_int < self.z3_len)

    def conditional_merge(self, other: AnySymbolic, condition: z3.BoolRef) -> SymbolicList:
        """Merge with another list based on condition."""
        if not isinstance(other, SymbolicList):
            from pyspectre.core.types import SymbolicValue

            return SymbolicValue.from_const(0)
        new_array = z3.If(condition, self.z3_array, other.z3_array)
        new_len = z3.If(condition, self.z3_len, other.z3_len)
        return SymbolicList(
            _name=f"If({condition}, {self._name}, {other.name})",
            z3_array=new_array,
            z3_len=new_len,
            element_type=self.element_type,
            taint_labels=(self.taint_labels or frozenset()) | (other.taint_labels or frozenset()),
        )

    def __repr__(self) -> str:
        return f"SymbolicList({self._name}, len={self.z3_len})"


@dataclass
class SymbolicDict(SymbolicType):
    """Symbolic dictionary using Z3 arrays.
    For simplicity, we model string-keyed dicts with int values.
    """

    _name: str
    z3_array: z3.ArrayRef
    known_keys: z3.SeqRef
    z3_len: z3.ArithRef
    taint_labels: set[str] | frozenset[str] | None = field(default=None, compare=False)

    @property
    def name(self) -> str:
        return self._name

    def to_z3(self) -> z3.ExprRef:
        return self.z3_array

    def could_be_truthy(self) -> z3.BoolRef:
        return self.z3_len > 0

    def could_be_falsy(self) -> z3.BoolRef:
        return self.z3_len == 0

    @staticmethod
    def symbolic(name: str) -> tuple[SymbolicDict, z3.BoolRef]:
        """Create a fresh symbolic dict."""
        z3_array = z3.Array(f"{name}_dict", z3.StringSort(), z3.IntSort())
        known_keys = z3.Empty(z3.SeqSort(z3.StringSort()))
        z3_len = z3.Int(f"{name}_len")
        constraint = z3_len >= 0
        return SymbolicDict(name, z3_array, known_keys, z3_len), constraint

    def __getitem__(self, key: SymbolicString) -> SymbolicValue:
        """Dict lookup."""
        elem = z3.Select(self.z3_array, key.z3_str)
        return SymbolicValue(
            _name=f"{self._name}[{key._name}]",
            z3_int=elem,
            is_int=z3.BoolVal(True),
            z3_bool=z3.BoolVal(False),
            is_bool=z3.BoolVal(False),
            taint_labels=(self.taint_labels or frozenset()) | (key.taint_labels or frozenset()),
        )

    def __setitem__(self, key: SymbolicString, value: SymbolicValue) -> SymbolicDict:
        """Dict assignment - returns new dict."""
        new_array = z3.Store(self.z3_array, key.z3_str, value.z3_int)
        return SymbolicDict(
            _name=f"{self._name}[{key._name}]={value._name}",
            z3_array=new_array,
            known_keys=self.known_keys,
            z3_len=self.z3_len,
            taint_labels=(self.taint_labels or frozenset())
            | (key.taint_labels or frozenset())
            | (value.taint_labels or frozenset()),
        )

    def contains_key(self, key: SymbolicString) -> SymbolicValue:
        """Check if key exists."""
        result = z3.Contains(self.known_keys, z3.Unit(key.z3_str))
        return SymbolicValue(
            _name=f"({key._name} in {self._name})",
            z3_int=z3.IntVal(0),
            is_int=z3.BoolVal(False),
            z3_bool=result,
            is_bool=z3.BoolVal(True),
            taint_labels=(self.taint_labels or frozenset()) | (key.taint_labels or frozenset()),
        )

    def conditional_merge(self, other: AnySymbolic, condition: z3.BoolRef) -> SymbolicDict:
        """Merge with another dict based on condition."""
        if not isinstance(other, SymbolicDict):
            from pyspectre.core.types import SymbolicValue

            return SymbolicValue.from_const(0)
        new_array = z3.If(condition, self.z3_array, other.z3_array)
        new_keys = z3.If(condition, self.known_keys, other.known_keys)
        new_len = z3.If(condition, self.z3_len, other.z3_len)
        return SymbolicDict(
            _name=f"If({condition}, {self._name}, {other.name})",
            z3_array=new_array,
            known_keys=new_keys,
            z3_len=new_len,
            taint_labels=(self.taint_labels or frozenset()) | (other.taint_labels or frozenset()),
        )

    def __repr__(self) -> str:
        return f"SymbolicDict({self._name})"


@dataclass
class SymbolicObject(SymbolicType):
    """Symbolic object references (with heap address).
    Attributes:
        _name: Debugging name
        address: Heap address (integer)
        z3_addr: Z3 integer representing the address
    """

    _name: str
    address: int
    z3_addr: z3.ArithRef
    potential_addresses: set[int] = field(default_factory=set)

    def __post_init__(self):
        if not self.potential_addresses and self.address != -1:
            self.potential_addresses = {self.address}

    @property
    def name(self) -> str:
        return self._name

    def to_z3(self) -> z3.ExprRef:
        return self.z3_addr

    def could_be_truthy(self) -> z3.BoolRef:
        return self.z3_addr != 0

    def could_be_falsy(self) -> z3.BoolRef:
        return self.z3_addr == 0

    @staticmethod
    def symbolic(name: str, address: int) -> tuple[SymbolicObject, z3.BoolRef]:
        """Create a fresh symbolic object pointer."""
        z3_addr = z3.IntVal(address)
        constraint = z3.BoolVal(True)
        return SymbolicObject(name, address, z3_addr, {address}), constraint

    @staticmethod
    def from_const(value: object) -> SymbolicObject:
        """Create from existing object (requires address management - usually caller handles this)."""
        addr = id(value)
        return SymbolicObject(f"obj_{addr}", addr, z3.IntVal(addr), {addr})

    def __eq__(self, other: object) -> SymbolicValue:
        if not isinstance(other, SymbolicObject):
            if isinstance(other, SymbolicNone):
                return SymbolicValue(
                    _name=f"({self._name} is None)",
                    z3_int=z3.IntVal(0),
                    is_int=z3.BoolVal(False),
                    z3_bool=self.z3_addr == 0,
                    is_bool=z3.BoolVal(True),
                )
            return SymbolicValue.from_const(False)
        return SymbolicValue(
            _name=f"({self._name}=={other._name})",
            z3_int=z3.IntVal(0),
            is_int=z3.BoolVal(False),
            z3_bool=self.z3_addr == other.z3_addr,
            is_bool=z3.BoolVal(True),
        )

    def __repr__(self) -> str:
        return f"SymbolicObject({self._name}, addr={self.address})"

    def conditional_merge(
        self, other: AnySymbolic, condition: z3.BoolRef
    ) -> SymbolicObject | SymbolicValue:
        """Merge with another object.
        If address is same, we assume object identity is same (merging state handled by caller/heap).
        If address differs, we create a symbolic pointer: If(cond, addr1, addr2).
        """
        if isinstance(other, SymbolicNone):
            new_addr = z3.If(condition, self.z3_addr, z3.IntVal(0))
            return SymbolicObject(
                _name=f"If({condition}, {self._name}, None)",
                address=-1,
                z3_addr=new_addr,
                potential_addresses=self.potential_addresses.copy(),
            )
        if isinstance(other, SymbolicObject):
            new_addr = z3.If(condition, self.z3_addr, other.z3_addr)
            return SymbolicObject(
                _name=f"If({condition}, {self._name}, {other.name})",
                address=-1 if self.address != other.address else self.address,
                z3_addr=new_addr,
                potential_addresses=self.potential_addresses.union(other.potential_addresses),
            )
        return SymbolicValue.from_const(0)


AnySymbolic = Union[
    SymbolicValue, SymbolicString, SymbolicList, SymbolicDict, SymbolicNone, SymbolicObject
]
