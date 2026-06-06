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

"""Tuple, integer-set, and iterator symbolic container carriers."""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Sized
from dataclasses import dataclass, field
import z3

from pysymex.core.identity.addressing import next_address
from pysymex.core.constants import Z3_FALSE, Z3_TRUE, Z3_ZERO
from pysymex.core.solver.constraints.hashing import get_int_val
from pysymex.core.types.containers.helpers import known_length_truthiness
from pysymex.core.types.numeric.bool import SymbolicBool
from pysymex.core.types.numeric.int import SymbolicInt
from pysymex.core.types.base import SymbolicType
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.core.types.scalars.values import fresh_name


@dataclass
class SymbolicTuple(SymbolicType):
    """Tuple wrapper retaining element objects for collection operations.

    Limitations:
        Its primary Z3 expression is only the first representable element
        (or zero), and symbolic index access currently returns a zero-valued
        placeholder rather than selecting an element.
    """

    elements: tuple[object, ...]
    _name: str = ""

    __hash__ = object.__hash__

    @property
    def name(self) -> str:
        """Return the diagnostic name for this retained tuple."""
        return self._name or "tuple"

    def to_z3(self) -> z3.ExprRef:
        """Return the first representable element expression, or integer zero."""
        if not self.elements:
            return Z3_ZERO
        head = self.elements[0]
        if isinstance(head, SymbolicType):
            return head.to_z3()
        if isinstance(head, int):
            return get_int_val(head)
        return Z3_ZERO

    def hash_value(self) -> int:
        """Return Python's structural hash of the retained element tuple."""
        return hash(self.elements)

    def could_be_truthy(self) -> z3.BoolRef:
        """Return the concrete predicate that retained tuple elements are present."""
        return Z3_TRUE if self.elements else Z3_FALSE

    def could_be_falsy(self) -> z3.BoolRef:
        """Return the concrete predicate that this retained tuple is empty."""
        return Z3_FALSE if self.elements else Z3_TRUE

    def __len__(self) -> int:
        """Return the concrete count of retained tuple elements."""
        return len(self.elements)

    def __getitem__(self, index: int | SymbolicInt) -> object:
        """Return a concrete-position item or a placeholder for symbolic indexes."""
        if isinstance(index, int):
            return self.elements[index]
        return SymbolicValue.from_const(0)

    def __iter__(self) -> Iterator[object]:
        """Iterate over the retained tuple elements."""
        return iter(self.elements)

    def __add__(self, other: SymbolicTuple) -> SymbolicTuple:
        """Return a tuple retaining both operand element sequences."""
        return SymbolicTuple(self.elements + other.elements)

    @staticmethod
    def from_elements(*elements: object) -> SymbolicTuple:
        """Create a tuple retaining the supplied element objects."""
        return SymbolicTuple(tuple(elements))


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

    def to_z3(self) -> z3.ExprRef:
        """Return the Z3 set expression representing integer membership."""
        return self.z3_set

    def hash_value(self) -> int:
        """Return a structural hash of the Z3 set expression."""
        return self.z3_set.hash()

    def could_be_truthy(self) -> z3.BoolRef:
        """Return the predicate that the modeled set length is positive."""
        if self._concrete_items is not None:
            return Z3_TRUE if self._concrete_items else Z3_FALSE
        return known_length_truthiness(self.length.value, truthy=True)

    def could_be_falsy(self) -> z3.BoolRef:
        """Return the predicate that the modeled set length is zero."""
        if self._concrete_items is not None:
            return Z3_FALSE if self._concrete_items else Z3_TRUE
        return known_length_truthiness(self.length.value, truthy=False)

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
                Z3_TRUE if elem.z3_int.as_long() in self._concrete_items else Z3_FALSE
            )
        return SymbolicBool(z3.IsMember(elem.z3_int, self.z3_set))

    def add(self, elem: SymbolicInt) -> SymbolicSet:
        """Return a new set with ``elem`` included."""
        concrete_items = None
        if self._concrete_items is not None and z3.is_int_value(elem.z3_int):
            concrete_items = frozenset({*self._concrete_items, elem.z3_int.as_long()})
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
    def symbolic_int_set(name: str | None = None) -> SymbolicSet:
        """Create an unconstrained symbolic integer-set expression."""
        set_name = name or fresh_name("set")
        return SymbolicSet(
            z3.Const(set_name, z3.SetSort(z3.IntSort())),
            z3.IntSort(),
            set_name,
        )

    @staticmethod
    def from_const(values: Iterable[int]) -> SymbolicSet:
        """Create an integer symbolic set from concrete set members."""
        concrete_items = frozenset(values)
        z3_set = z3.EmptySet(z3.IntSort())
        for value in sorted(concrete_items):
            z3_set = z3.SetAdd(z3_set, get_int_val(value))
        return SymbolicSet(
            z3_set,
            z3.IntSort(),
            repr(set(concrete_items)),
            _concrete_items=concrete_items,
        )


@dataclass(slots=True)
class SymbolicIterator(SymbolicType):
    """Iterator bookkeeping record for one source object and current index.

    Limitations:
        Its primary Z3 expression is constant zero and its truthiness is
        always modeled as true; iteration termination is tracked separately
        through :meth:`remaining_bound`.
    """

    _name: str
    iterable: object
    index: int = 0
    is_generator: bool = False
    reverse: bool = False
    source_size: int | None = None
    size_change_raises: bool = False
    exhausted: bool = False
    _iterator_id: int = field(default_factory=next_address, repr=False, compare=False)

    @property
    def name(self) -> str:
        """Return the diagnostic name for this iterator record."""
        return self._name

    def to_z3(self) -> z3.ExprRef:
        """Return the constant placeholder expression for iterator values."""
        return Z3_ZERO

    def hash_value(self) -> int:
        """Return a process-local identity/index structural hash."""
        return (self._iterator_id * 31) ^ self.index

    def could_be_truthy(self) -> z3.BoolRef:
        """Return the modeled invariant that iterator objects are truthy."""
        return Z3_TRUE

    def could_be_falsy(self) -> z3.BoolRef:
        """Return the modeled invariant that iterator objects are not falsy."""
        return Z3_FALSE

    def __repr__(self) -> str:
        """Return a diagnostic representation of source and current index."""
        status = ", exhausted=True" if self.exhausted else ""
        return f"SymbolicIterator(of {self.iterable}, index={self.index}{status})"

    def advance(self) -> SymbolicIterator:
        """Return a new iterator record with an incremented index and identity."""
        import dataclasses

        return dataclasses.replace(
            self,
            index=self.index + 1,
            _iterator_id=next_address(),
        )

    def exhaust(self) -> SymbolicIterator:
        """Return a new iterator record marked permanently exhausted."""
        import dataclasses

        return dataclasses.replace(
            self,
            exhausted=True,
            _iterator_id=next_address(),
        )

    def remaining_bound(self) -> int | z3.ArithRef:
        """Return exact sized remainder or a fresh nonnegative expression.

        Notes:
            For unsized sources, the expression is not constrained by the
            source object in this method.
        """
        if self.exhausted:
            return 0
        if isinstance(self.iterable, Sized):
            length = len(self.iterable)
            return length - self.index
        unknown_remaining = z3.Int(f"{self._name}_remaining_{self._iterator_id}_{self.index}")
        return z3.If(unknown_remaining >= 0, unknown_remaining, 0)
