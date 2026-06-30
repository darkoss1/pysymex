# pysymex: python symbolic execution & formal verification
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

"""Shared base protocol and ``None`` value for symbolic type representations.

This module owns common symbolic-value hooks and context-bound fresh-name
allocation used by concrete and union-like symbolic implementations.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE

if TYPE_CHECKING:
    import z3

    from pysymex._internal.core.types.scalars.values import SymbolicValue


class TypeTag(Enum):
    """Type discriminators produced by active symbolic numeric carriers."""

    BOOL = auto()
    INT = auto()
    FLOAT = auto()
    UNKNOWN = auto()


@runtime_checkable
class _SupportsIsNone(Protocol):
    """Expose a symbolic predicate for membership in the ``None`` type."""

    @property
    def is_none(self) -> z3.BoolRef:
        """Return the expression indicating whether this value is ``None``."""
        ...


def _next_address() -> int:
    """Resolve the shared address counter lazily to avoid import cycles."""
    from pysymex._internal.core.identity.addressing import next_address

    return next_address()


def fresh_name(prefix: str) -> str:
    """Return the next context-bound generated name for ``prefix``.

    Notes:
        The counter is stored through
        :func:`pysymex._internal.core.identity.addressing.next_address`. Distinct contexts
        may use independent counters when established or reset separately;
        this function alone does not guarantee cross-context uniqueness.

    """
    return f"{prefix}_{_next_address()}"


class SymbolicType(ABC):
    """Interface implemented by symbolic values used by execution.

    Concrete subclasses provide a primary Z3 expression and truthiness
    behavior; equality helpers build Z3 predicates over those representations.

    Limitations:
        A primary expression or structural hash does not represent every
        semantic field carried by richer symbolic subclasses.
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
        """Return the primary-expression structural hash used in state summaries."""
        return self.to_z3().hash()

    def symbolic_length(self) -> z3.ArithRef | None:
        """Return this value's Python length expression, when it has one."""
        return None

    def symbolic_eq(self, other: SymbolicType) -> z3.BoolRef:
        """Return equality of primary Z3 expressions with mismatched sorts rejected."""
        self_expr = self.to_z3()
        other_expr = other.to_z3()
        if self_expr.sort() != other_expr.sort():
            return Z3_FALSE
        return self_expr == other_expr

    def __repr__(self) -> str:
        """Return a diagnostic representation containing type and name."""
        return f"{self.__class__.__name__}({self.name})"


@dataclass(slots=True)
class SymbolicNoneType(SymbolicType):
    """Symbolic representation of Python's singleton ``None`` value.

    Every instance is falsy and compares symbolically equal to another
    ``SymbolicNoneType``. Equality against union-like values delegates to
    their ``is_none`` discriminator when exposed.
    """

    _name: str = "None"
    _h_active: bool = field(default=False)

    def __post_init__(self) -> None:
        """Bound diagnostic names and retain self/cls affinity metadata."""
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
        """Return the diagnostic name for the modeled ``None`` value."""
        return self._name

    def to_z3(self) -> z3.ExprRef:
        """Return the constant false primary expression for ``None``."""
        return Z3_FALSE

    def is_truthy(self) -> z3.BoolRef:
        """Return the invariant that ``None`` is never truthy."""
        return Z3_FALSE

    def is_falsy(self) -> z3.BoolRef:
        """Return the invariant that ``None`` is always falsy."""
        return Z3_TRUE

    def symbolic_eq(self, other: SymbolicType) -> z3.BoolRef:
        """Return equality with ``None`` carriers or a provided ``is_none`` predicate."""
        if isinstance(other, SymbolicNoneType):
            return Z3_TRUE
        if isinstance(other, _SupportsIsNone):
            return other.is_none
        return Z3_FALSE

    def hash_value(self) -> int:
        """Return the stable structural hash for the modeled singleton value."""
        return hash("SymbolicNone")

    def conditional_merge(
        self,
        other: object,
        condition: z3.BoolRef,
    ) -> SymbolicNoneType | SymbolicValue:
        """Return ``None`` unchanged or delegate heterogeneous merging to ``SymbolicValue``."""
        if isinstance(other, SymbolicNoneType):
            return self
        from pysymex._internal.core.types.scalars.values import SymbolicValue

        return SymbolicValue.from_specialized(self).conditional_merge(other, condition)

    @property
    def is_int(self) -> z3.BoolRef:
        """Return the invariant that ``None`` is not an integer."""
        return Z3_FALSE

    @property
    def is_bool(self) -> z3.BoolRef:
        """Return the invariant that ``None`` is not a Boolean."""
        return Z3_FALSE

    @property
    def is_float(self) -> z3.BoolRef:
        """Return the invariant that ``None`` is not a float."""
        return Z3_FALSE

    @property
    def is_str(self) -> z3.BoolRef:
        """Return the invariant that ``None`` is not a string."""
        return Z3_FALSE

    @property
    def is_none(self) -> z3.BoolRef:
        """Return the invariant that this carrier represents ``None``."""
        return Z3_TRUE

    @property
    def is_path(self) -> z3.BoolRef:
        """Return the invariant that ``None`` is not a path value."""
        return Z3_FALSE

    @property
    def is_obj(self) -> z3.BoolRef:
        """Return the invariant that ``None`` is not a modeled object."""
        return Z3_FALSE

    @property
    def is_list(self) -> z3.BoolRef:
        """Return the invariant that ``None`` is not a list."""
        return Z3_FALSE

    @property
    def is_dict(self) -> z3.BoolRef:
        """Return the invariant that ``None`` is not a dictionary."""
        return Z3_FALSE

    @property
    def is_bytes(self) -> z3.BoolRef:
        """Return the invariant that ``None`` is not bytes."""
        return Z3_FALSE

    @property
    def is_tuple(self) -> z3.BoolRef:
        """Return the invariant that ``None`` is not a tuple."""
        return Z3_FALSE

    @property
    def is_set(self) -> z3.BoolRef:
        """Return the invariant that ``None`` is not a set."""
        return Z3_FALSE

    def __repr__(self) -> str:
        """Return the stable diagnostic representation for ``None``."""
        return "SymbolicNone()"
