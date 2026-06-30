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

"""Symbolic iterator bookkeeping records shared across execution and models."""

from __future__ import annotations

from collections.abc import Sized
from dataclasses import dataclass, field

import z3

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE, Z3_ZERO
from pysymex._internal.core.identity.addressing import next_address
from pysymex._internal.core.types.base import SymbolicType


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
