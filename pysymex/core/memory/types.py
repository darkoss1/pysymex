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

"""Typed address, heap-object, and stack-frame values for the memory model."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto

from pysymex.core.constants import Z3_TRUE
from pysymex.core.solver.constraints.hashing import get_bitvec_val
import z3


class MemoryRegion(Enum):
    """Coarse symbolic address spaces treated as distinct by alias queries."""

    STACK = auto()
    HEAP = auto()
    GLOBAL = auto()
    CONST = auto()


@dataclass(slots=True)
class SymbolicAddress:
    """Region-tagged bit-vector base and offset used by the heap model.

    Address arithmetic constructs Z3 bit-vector expressions. The region tag
    provides a model-level non-alias partition; it is not an operating-system
    isolation or memory-safety guarantee.
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
        """Construct a region-tagged 64-bit symbolic address."""
        self.region = region
        self.type_tag = type_tag
        if isinstance(base, int):
            self.base = get_bitvec_val(base, self.ADDR_WIDTH)
        else:
            self.base = base
        if isinstance(offset, int):
            self.offset = get_bitvec_val(offset, self.ADDR_WIDTH)
        else:
            self.offset = offset

    @property
    def effective_address(self) -> z3.BitVecRef:
        """Return the 64-bit bit-vector expression ``base + offset``."""
        return self.base + self.offset

    def same_region(self, other: SymbolicAddress) -> bool:
        """Return whether model-level region tags are equal."""
        return self.region == other.region

    def __repr__(self) -> str:
        """Return the diagnostic representation for this address."""
        return f"SymbolicAddress({self.region.name}, base={self.base}, offset={self.offset})"

    def __eq__(self, other: object) -> bool:
        """Return structural equality for region, base, and offset."""
        if not isinstance(other, SymbolicAddress):
            return False
        return (
            self.region == other.region
            and z3.eq(self.base, other.base)
            and z3.eq(self.offset, other.offset)
        )

    def __hash__(self) -> int:
        """Return a process hash over region and Z3 expression hashes."""
        base_h = self.base.hash() if hasattr(self.base, "hash") else hash(self.base)
        offset_h = self.offset.hash() if hasattr(self.offset, "hash") else hash(self.offset)
        return hash((self.region, base_h, offset_h))


@dataclass(slots=True)
class HeapObject:
    """Mutable heap record containing fields and an optional liveness formula."""

    address: SymbolicAddress
    type_name: str
    fields: dict[str, object] = field(default_factory=lambda: dict[str, object]())
    is_mutable: bool = True
    size: int = 1
    is_alive: z3.BoolRef = field(default_factory=lambda: Z3_TRUE)

    def get_field(self, name: str) -> object:
        """Return a field value, using ``None`` for an absent field."""
        return self.fields.get(name)

    def set_field(self, name: str, value: object) -> None:
        """Store a field value unless this heap object is marked immutable.

        Raises:
            ValueError: If ``is_mutable`` is ``False``.
        """
        if not self.is_mutable:
            raise ValueError(f"Cannot modify immutable object of type {self.type_name}")
        self.fields[name] = value

    def has_field(self, name: str) -> bool:
        """Return whether ``name`` is present in this object's field mapping."""
        return name in self.fields


@dataclass(slots=True)
class StackFrame:
    """Mutable function-frame record containing local variables and its parent."""

    function_name: str
    locals: dict[str, object] = field(default_factory=lambda: dict[str, object]())
    return_address: int | None = None
    parent_frame: StackFrame | None = None

    def get_local(self, name: str) -> object:
        """Return a local value, using ``None`` for an absent binding."""
        return self.locals.get(name)

    def set_local(self, name: str, value: object) -> None:
        """Store ``value`` under local-variable name ``name``."""
        self.locals[name] = value
