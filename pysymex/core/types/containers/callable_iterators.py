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

"""Carrier for CPython's two-argument ``iter(callable, sentinel)`` object."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING

import z3

from pysymex.core.constants import Z3_FALSE, Z3_TRUE, Z3_ZERO
from pysymex.core.identity.addressing import next_address
from pysymex.core.types.base import SymbolicType

if TYPE_CHECKING:
    from pysymex.typing import StackValue


@dataclass(frozen=True, slots=True)
class CallableSentinelIterator(SymbolicType):
    """Represent the iterator returned by ``iter(callable, sentinel)``.

    The VM owns executing the producer at each ``FOR_ITER`` step; this carrier only
    preserves the producer, sentinel, and iteration identity.
    """

    _name: str
    producer: StackValue
    sentinel: StackValue
    index: int = 0
    _iterator_id: int = field(default_factory=next_address, repr=False, compare=False)

    @property
    def name(self) -> str:
        """Return the diagnostic name for this callable-sentinel iterator."""
        return self._name

    def to_z3(self) -> z3.ExprRef:
        """Return the constant placeholder expression for iterator identity."""
        return Z3_ZERO

    def hash_value(self) -> int:
        """Return a structural hash over producer, sentinel, and current index."""
        return hash((self._iterator_id, self.index, self.producer, self.sentinel))

    def could_be_truthy(self) -> z3.BoolRef:
        """Return the modeled invariant that iterator objects are truthy."""
        return Z3_TRUE

    def could_be_falsy(self) -> z3.BoolRef:
        """Return the modeled invariant that iterator objects are not falsy."""
        return Z3_FALSE

    def advance(self) -> CallableSentinelIterator:
        """Return a new iterator record advanced by one producer call."""
        return replace(self, index=self.index + 1, _iterator_id=next_address())


__all__ = ["CallableSentinelIterator"]
