# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""
pysymex Memory Model - Type definitions
Dataclasses, enums, and type-only classes for the memory model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto

import z3


class MemoryRegion(Enum):
    """Different memory regions with isolation guarantees."""

    STACK = auto()
    HEAP = auto()
    GLOBAL = auto()
    CONST = auto()


@dataclass(slots=True)
class SymbolicAddress:
    """
    A symbolic memory address.

    **Mathematical Representation:**
    Modeled as an algebraic triple: `(Region, Base, Offset)`.
    - `Base` and `Offset` are Z3 BitVectors (typically 64-bit).
    - `Region` provides coarse-grained isolation (e.g., Stack vs Heap).

    **Arithmetic Semantics:**
    Supports precise address arithmetic (addition/subtraction) using bitvector
    theory. This allows modeling pointer arithmetic, buffer overflows, and
    struct/array indexing with high fidelity.
    """

    region: MemoryRegion
    base: z3.BitVecRef
    offset: z3.BitVecRef
    type_tag: str
    ADDR_WIDTH = 64

    def __init__(
        self,
        region: MemoryRegion,
        base: int | z3.BitVecRef,
        offset: int | z3.BitVecRef = 0,
        type_tag: str = "unknown",
    ) -> None:
        self.region = region
        self.type_tag = type_tag
        if isinstance(base, int):
            self.base = z3.BitVecVal(base, self.ADDR_WIDTH)
        else:
            self.base = base
        if isinstance(offset, int):
            self.offset = z3.BitVecVal(offset, self.ADDR_WIDTH)
        else:
            self.offset = offset

    @property
    def effective_address(self) -> z3.BitVecRef:
        """Compute the effective address (base + offset)."""
        return self.base + self.offset

    def add_offset(self, delta: int | z3.BitVecRef) -> SymbolicAddress:
        """Create a new address with additional offset."""
        if isinstance(delta, int):
            delta = z3.BitVecVal(delta, self.ADDR_WIDTH)
        return SymbolicAddress(
            region=self.region, base=self.base, offset=self.offset + delta, type_tag=self.type_tag
        )

    def same_region(self, other: SymbolicAddress) -> bool:
        """Check if two addresses are in the same region."""
        return self.region == other.region

    def may_alias(self, other: SymbolicAddress, solver: z3.Solver) -> bool:
        """
        Check if two addresses may refer to the same location.

        **Aliasing Constraint:**
        Returns SAT if there exists a model where `addr1.effective == addr2.effective`
        AND they reside in the same memory region.
        Regions provide a sound optimization for non-aliasing; addresses in
        different regions (e.g. Stack and Const) are assumed never to alias.
        """
        if not self.same_region(other):
            return False
        solver.push()
        solver.add(self.effective_address == other.effective_address)
        result = solver.check() == z3.sat
        solver.pop()
        return result

    def must_alias(self, other: SymbolicAddress, solver: z3.Solver) -> bool:
        """
        Check if two addresses must refer to the same location.
        Returns True only if addresses are provably equal.
        """
        if not self.same_region(other):
            return False
        solver.push()
        solver.add(self.effective_address != other.effective_address)
        result = solver.check() == z3.unsat
        solver.pop()
        return result

    def __repr__(self) -> str:
        return f"SymbolicAddress({self.region.name}, base={self.base}, offset={self.offset})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SymbolicAddress):
            return False
        return (
            self.region == other.region
            and z3.eq(self.base, other.base)
            and z3.eq(self.offset, other.offset)
        )

    def __hash__(self) -> int:
        """Return the hash value of the object."""
        return hash((self.region, str(self.base), str(self.offset)))


@dataclass(slots=True)
class HeapObject:
    """
    A symbolic object stored on the heap.
    Represents Python objects with their fields/attributes stored symbolically.
    """

    address: SymbolicAddress
    type_name: str
    fields: dict[str, object] = field(default_factory=lambda: dict[str, object]())
    is_mutable: bool = True
    size: int = 1
    is_alive: z3.BoolRef = field(default_factory=lambda: z3.BoolVal(True))

    def get_field(self, name: str) -> object:
        """Get a field value, returning None if not present."""
        return self.fields.get(name)

    def set_field(self, name: str, value: object) -> None:
        """Set a field value."""
        if not self.is_mutable:
            raise ValueError(f"Cannot modify immutable object of type {self.type_name}")
        self.fields[name] = value

    def has_field(self, name: str) -> bool:
        """Check if the object has a field."""
        return name in self.fields


@dataclass(slots=True)
class StackFrame:
    """
    A symbolic stack frame for function calls.
    Tracks local variables and their values within a function scope.
    """

    function_name: str
    locals: dict[str, object] = field(default_factory=lambda: dict[str, object]())
    return_address: int | None = None
    parent_frame: StackFrame | None = None

    def get_local(self, name: str) -> object:
        """Get a local variable value."""
        return self.locals.get(name)

    def set_local(self, name: str, value: object) -> None:
        """Set a local variable value."""
        self.locals[name] = value

    def has_local(self, name: str) -> bool:
        """Check if a local variable exists."""
        return name in self.locals

    def delete_local(self, name: str) -> None:
        """Delete a local variable."""
        if name in self.locals:
            del self.locals[name]


__all__ = [
    "HeapObject",
    "MemoryRegion",
    "StackFrame",
    "SymbolicAddress",
]
