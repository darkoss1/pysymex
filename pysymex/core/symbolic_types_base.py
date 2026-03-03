"""Base types for the symbolic type system.

Provides the ``TypeTag`` enum, name-generation utilities, and the
``SymbolicType`` abstract base class that every symbolic type inherits.
Also defines ``SymbolicNoneType`` and the global ``SYMBOLIC_NONE`` singleton.
"""

from __future__ import annotations


from abc import ABC, abstractmethod

from dataclasses import dataclass, field

from enum import Enum, auto


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
