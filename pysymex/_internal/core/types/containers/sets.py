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

"""Integer-element symbolic set carrier with optional concrete retention."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.base import SymbolicType, fresh_name
from pysymex._internal.core.types.containers.storage_ops import ContainerStorageOps
from pysymex._internal.core.types.numeric.bool import SymbolicBool
from pysymex._internal.core.types.numeric.int import SymbolicInt

if TYPE_CHECKING:
    from collections.abc import Iterable


@dataclass
class SymbolicSet(SymbolicType):
    """Integer-element symbolic set backed by Z3 set expressions.

    Concrete-backed sets retain exact integer members. For general symbolic
    sets, membership is modeled by Z3 while the lazily created length has no
    relationship constraint to the set contents in this class.
    """

    z3_set: z3.ArrayRef
    element_sort: z3.SortRef
    _name: str = ""
    _concrete_items: frozenset[int] | None = field(default=None, compare=False)

    __hash__ = object.__hash__

    @property
    def name(self) -> str:
        """Return the diagnostic name for this symbolic set."""
        return self._name or "set"

    @property
    def is_set(self) -> z3.BoolRef:
        """Return the definite set-type marker."""
        return Z3_TRUE

    def to_z3(self) -> z3.ExprRef:
        """Return the Z3 set expression representing integer membership."""
        return self.z3_set

    def hash_value(self) -> int:
        """Return a structural hash of the Z3 set expression."""
        return self.z3_set.hash()

    def symbolic_length(self) -> z3.ArithRef:
        """Return the represented set length."""
        return self.length.z3_int

    def could_be_truthy(self) -> z3.BoolRef:
        """Return the predicate that the modeled set length is positive."""
        if self._concrete_items is not None:
            return Z3_TRUE if self._concrete_items else Z3_FALSE
        return ContainerStorageOps.known_length_truthiness(self.length.value, truthy=True)

    def could_be_falsy(self) -> z3.BoolRef:
        """Return the predicate that the modeled set length is zero."""
        if self._concrete_items is not None:
            return Z3_FALSE if self._concrete_items else Z3_TRUE
        return ContainerStorageOps.known_length_truthiness(self.length.value, truthy=False)

    @property
    def length(self) -> SymbolicInt:
        """Return exact concrete length or a cached unconstrained symbolic integer."""
        if self._concrete_items is not None:
            return SymbolicInt.concrete(len(self._concrete_items))
        if not hasattr(self, "_cached_length"):
            self._cached_length = SymbolicInt(z3.Int(fresh_name(f"set_len_{self.name}")))
        return self._cached_length

    @property
    def concrete_items(self) -> frozenset[int] | None:
        """Return exact retained integer members when this set is concrete-backed."""
        return self._concrete_items

    def contains(self, elem: SymbolicInt) -> SymbolicBool:
        """Return concrete or Z3-set integer membership for ``elem``."""
        if self._concrete_items is not None and z3.is_int_value(elem.z3_int):
            return SymbolicBool(
                Z3_TRUE if elem.z3_int.as_long() in self._concrete_items else Z3_FALSE,
            )
        return SymbolicBool(z3.IsMember(elem.z3_int, self.z3_set))

    def add(self, elem: SymbolicInt) -> SymbolicSet:
        """Return a new set with ``elem`` included."""
        concrete_items = None
        if self._concrete_items is not None and z3.is_int_value(elem.z3_int):
            concrete_items = frozenset((*self._concrete_items, elem.z3_int.as_long()))
        return SymbolicSet(
            z3.SetAdd(self.z3_set, elem.z3_int),
            self.element_sort,
            _concrete_items=concrete_items,
        )

    def remove(self, elem: SymbolicInt) -> SymbolicSet:
        """Return a new set with ``elem`` removed."""
        concrete_items = None
        if self._concrete_items is not None and z3.is_int_value(elem.z3_int):
            concrete_items = frozenset(
                item for item in self._concrete_items if item != elem.z3_int.as_long()
            )
        return SymbolicSet(
            z3.SetDel(self.z3_set, elem.z3_int),
            self.element_sort,
            _concrete_items=concrete_items,
        )

    def union(self, other: SymbolicSet) -> SymbolicSet:
        """Return a new union, retaining exact members only when both inputs do."""
        concrete_items = (
            self._concrete_items | other._concrete_items
            if self._concrete_items is not None and other._concrete_items is not None
            else None
        )
        return SymbolicSet(
            z3.SetUnion(self.z3_set, other.z3_set),
            self.element_sort,
            _concrete_items=concrete_items,
        )

    def intersection(self, other: SymbolicSet) -> SymbolicSet:
        """Return a new intersection, retaining exact members only for concrete inputs."""
        concrete_items = (
            self._concrete_items & other._concrete_items
            if self._concrete_items is not None and other._concrete_items is not None
            else None
        )
        return SymbolicSet(
            z3.SetIntersect(self.z3_set, other.z3_set),
            self.element_sort,
            _concrete_items=concrete_items,
        )

    def difference(self, other: SymbolicSet) -> SymbolicSet:
        """Return a new difference, retaining exact members only for concrete inputs."""
        concrete_items = (
            self._concrete_items - other._concrete_items
            if self._concrete_items is not None and other._concrete_items is not None
            else None
        )
        return SymbolicSet(
            z3.SetDifference(self.z3_set, other.z3_set),
            self.element_sort,
            _concrete_items=concrete_items,
        )

    def issubset(self, other: SymbolicSet) -> SymbolicBool:
        """Return the Z3 subset predicate for two set expressions."""
        return SymbolicBool(z3.IsSubset(self.z3_set, other.z3_set))

    @staticmethod
    def symbolic(name: str) -> tuple[SymbolicSet, z3.BoolRef]:
        """Create a general integer set and its nonnegative-length constraint."""
        z3_set = z3.Const(f"{name}_set", z3.SetSort(z3.IntSort()))
        result = SymbolicSet(z3_set, z3.IntSort(), name)
        return result, result.length.z3_int >= 0

    @staticmethod
    def from_const(values: Iterable[int]) -> SymbolicSet:
        """Create an integer symbolic set from concrete set members."""
        concrete_items = frozenset(values)
        z3_set = z3.EmptySet(z3.IntSort())
        for value in sorted(concrete_items):
            z3_set = z3.SetAdd(z3_set, ConstraintValues.int(value))
        return SymbolicSet(
            z3_set,
            z3.IntSort(),
            repr(set(concrete_items)),
            _concrete_items=concrete_items,
        )
