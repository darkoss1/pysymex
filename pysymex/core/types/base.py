# pysymex: Python Symbolic Execution & Formal Verification
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

"""Base types for the symbolic type system.

Provides the ``TypeTag`` enum, name-generation utilities, and the
``SymbolicType`` abstract base class that every symbolic type inherits.
Also defines ``SymbolicNoneType`` and the global ``SYMBOLIC_NONE`` singleton.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Protocol, runtime_checkable

import z3

from pysymex.core.constants import Z3_FALSE, Z3_TRUE

if TYPE_CHECKING:
    from pysymex.core.types.scalars import AnySymbolic


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


@runtime_checkable
class _SupportsIsNone(Protocol):
    @property
    def is_none(self) -> z3.BoolRef: ...


def _next_address() -> int:
    """Resolve the shared address counter lazily to avoid import cycles."""
    from pysymex.core.memory.addressing import next_address

    return next_address()


def fresh_name(prefix: str) -> str:
    """Generate a unique name for a symbolic variable.

    Delegates to :func:`pysymex.core.memory.addressing.next_address` which
    uses a ``contextvars.ContextVar`` counter, giving each async session its
    own isolated namespace and eliminating cross-session Z3 variable collisions.
    """
    return f"{prefix}_{_next_address()}"


def reset_counters() -> None:
    """Reset name counters (for testing).

    Delegates to :func:`pysymex.core.memory.addressing.reset` so the
    counter restart is scoped to the current execution context.
    """
    from pysymex.core.memory.addressing import reset

    reset()


class SymbolicType(ABC):
    """Abstract base class for all symbolic types.
    Every symbolic type must:
    1. Have a type tag for runtime dispatch
    2. Convert to a Z3 expression
    3. Define truthiness semantics
    4. Support equality comparison
    """

    @property
    def type_tag(self) -> TypeTag | str:
        """Get the type discriminator."""
        return TypeTag.UNKNOWN

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name for debugging."""

    @abstractmethod
    def to_z3(self) -> z3.ExprRef:
        """Convert to primary Z3 expression."""

    def is_truthy(self) -> z3.BoolRef:
        """Z3 expression for when this value is truthy."""
        return self.could_be_truthy()

    def is_falsy(self) -> z3.BoolRef:
        """Z3 expression for when this value is falsy."""
        return self.could_be_falsy()

    def could_be_truthy(self) -> z3.BoolRef:
        """Canonical execution-layer truthiness expression."""
        return self.is_truthy()

    def could_be_falsy(self) -> z3.BoolRef:
        """Canonical execution-layer falsiness expression."""
        return self.is_falsy()

    def hash_value(self) -> int:
        """Stable content hash used by VM state deduplication."""
        return self.to_z3().hash()

    def symbolic_eq(self, other: SymbolicType) -> z3.BoolRef:
        """Z3 equality expression."""
        self_expr = self.to_z3()
        other_expr = other.to_z3()
        if self_expr.sort() != other_expr.sort():
            return Z3_FALSE
        return self_expr == other_expr

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.name})"


@dataclass(slots=True)
class SymbolicNoneType(SymbolicType):
    """Symbolic representation of Python None.
    None is a singleton - all None values are equal.
    Always falsy.
    """

    _name: str = "None"
    _h_active: bool = field(default=False)

    def __post_init__(self) -> None:
        if self._name:
            if len(self._name) > 256:
                self._name = self._name[:128] + "..." + self._name[-125:]
            lowered_name = self._name.lower()
            if lowered_name in ("self", "cls") or lowered_name.startswith(("self_", "cls_")):
                self._h_active = True

    @property
    def type_tag(self) -> str:
        """Property returning the type_tag."""
        return "NoneType"

    @property
    def name(self) -> str:
        return self._name

    def to_z3(self) -> z3.ExprRef:
        return Z3_FALSE

    def is_truthy(self) -> z3.BoolRef:
        return Z3_FALSE

    def is_falsy(self) -> z3.BoolRef:
        return Z3_TRUE

    def symbolic_eq(self, other: SymbolicType) -> z3.BoolRef:
        if isinstance(other, SymbolicNoneType):
            return Z3_TRUE
        if isinstance(other, _SupportsIsNone):
            return other.is_none
        return Z3_FALSE

    def hash_value(self) -> int:
        return hash("SymbolicNone")

    def conditional_merge(self, other: AnySymbolic, condition: z3.BoolRef) -> AnySymbolic:
        """Merge with another value based on a condition."""
        if isinstance(other, SymbolicNoneType):
            return self
        from pysymex.core.types.scalars import SymbolicValue

        return SymbolicValue.from_specialized(self).conditional_merge(other, condition)

    @property
    def is_int(self) -> z3.BoolRef:
        return Z3_FALSE

    @property
    def is_bool(self) -> z3.BoolRef:
        return Z3_FALSE

    @property
    def is_float(self) -> z3.BoolRef:
        return Z3_FALSE

    @property
    def is_str(self) -> z3.BoolRef:
        return Z3_FALSE

    @property
    def is_none(self) -> z3.BoolRef:
        return Z3_TRUE

    @property
    def is_path(self) -> z3.BoolRef:
        return Z3_FALSE

    @property
    def is_obj(self) -> z3.BoolRef:
        return Z3_FALSE

    @property
    def is_list(self) -> z3.BoolRef:
        return Z3_FALSE

    @property
    def is_dict(self) -> z3.BoolRef:
        return Z3_FALSE

    def __repr__(self) -> str:
        return "SymbolicNone()"


SYMBOLIC_NONE = SymbolicNoneType()


def safe_z3_eq(a: object, b: object) -> bool:
    """Return True if two Z3 expressions are structurally and contextually identical."""
    if a is b:
        return True
    if not isinstance(a, z3.ExprRef) or not isinstance(b, z3.ExprRef):
        return False
    if a.ctx is not b.ctx:
        return False
    try:
        return bool(z3.eq(a, b))
    except z3.Z3Exception:
        return False
