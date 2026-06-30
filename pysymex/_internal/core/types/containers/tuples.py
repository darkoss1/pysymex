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

"""Tuple symbolic container carrier retaining exact element objects."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE, Z3_ZERO
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.base import SymbolicType
from pysymex._internal.core.types.scalars.values import SymbolicValue

if TYPE_CHECKING:
    from collections.abc import Iterator

    from pysymex._internal.core.types.numeric.int import SymbolicInt


@dataclass
class SymbolicTuple(SymbolicType):
    """Tuple wrapper retaining element objects for collection operations.

    Concrete integer indexes return the exact retained object. Symbolic integer
    indexes produce an integer-channel expression over retained payloads after
    CPython-style negative-index normalization.

    Limitations:
        Its primary Z3 expression is only the first representable element (or
        zero). Symbolic index access preserves integer-channel payloads; items
        without an integer-channel representation contribute zero on their
        selected branch.
    """

    elements: tuple[object, ...]
    _name: str = ""

    __hash__ = object.__hash__

    @property
    def name(self) -> str:
        """Return the diagnostic name for this retained tuple."""
        return self._name or "tuple"

    @property
    def is_tuple(self) -> z3.BoolRef:
        """Return the definite tuple-type marker."""
        return Z3_TRUE

    def to_z3(self) -> z3.ExprRef:
        """Return the first representable element expression, or integer zero."""
        if not self.elements:
            return Z3_ZERO
        head = self.elements[0]
        if isinstance(head, SymbolicType):
            return head.to_z3()
        if isinstance(head, int):
            return ConstraintValues.int(head)
        return Z3_ZERO

    def hash_value(self) -> int:
        """Return Python's structural hash of the retained element tuple."""
        return hash(self.elements)

    def symbolic_length(self) -> z3.ArithRef:
        """Return the exact retained tuple length."""
        return ConstraintValues.int(len(self.elements))

    def could_be_truthy(self) -> z3.BoolRef:
        """Return the concrete predicate that retained tuple elements are present."""
        return Z3_TRUE if self.elements else Z3_FALSE

    def could_be_falsy(self) -> z3.BoolRef:
        """Return the concrete predicate that this retained tuple is empty."""
        return Z3_FALSE if self.elements else Z3_TRUE

    def __len__(self) -> int:
        """Return the concrete count of retained tuple elements."""
        return len(self.elements)

    def __getitem__(self, index: int | SymbolicInt | SymbolicValue) -> object:
        """Return a concrete-position item or symbolic integer-channel selection."""
        if isinstance(index, int):
            return self.elements[index]

        index_expr = index.z3_int
        real_idx = z3.If(index_expr < 0, index_expr + len(self.elements), index_expr)
        selected = self._element_expr_at(real_idx)
        return SymbolicValue.from_z3(selected, f"{self.name}[{index.name}]")

    def in_bounds(self, index: SymbolicInt | SymbolicValue) -> z3.BoolRef:
        """Return the Python-style valid-index predicate for this tuple."""
        length = len(self.elements)
        return z3.And(index.z3_int >= -length, index.z3_int < length)

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

    def _element_expr_at(self, index: z3.ArithRef) -> z3.ArithRef:
        """Return an integer-channel expression selected by a normalized index."""
        selected = Z3_ZERO
        for position, element in reversed(tuple(enumerate(self.elements))):
            selected = z3.If(index == position, _element_int_expr(element), selected)
        return selected


def _element_int_expr(element: object) -> z3.ArithRef:
    """Return the integer-channel expression retained for a tuple element."""
    if isinstance(element, bool):
        return ConstraintValues.int(int(element))
    if isinstance(element, int):
        return ConstraintValues.int(element)
    if isinstance(element, SymbolicType):
        expr = element.to_z3()
        if isinstance(expr, z3.ArithRef) and z3.is_int(expr):
            return expr
    return Z3_ZERO
